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
#include <time.h>

#include <windows.h>
#include <wincrypt.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/x509.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscrypto/crypto.h>
#include <xmlsec/mscrypto/x509.h>
#include <xmlsec/mscrypto/certkeys.h>


/*************************************************************************
 *
 * X509 utility functions
 *
 ************************************************************************/
static int		xmlSecMSCryptoX509DataNodeRead		(xmlSecKeyDataPtr data,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecMSCryptoX509CertificateNodeRead	(xmlSecKeyDataPtr data,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecMSCryptoX509CertificateNodeWrite	(PCCERT_CONTEXT cert,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecMSCryptoX509SubjectNameNodeRead	(xmlSecKeyDataPtr data,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecMSCryptoX509SubjectNameNodeWrite	(PCCERT_CONTEXT cert,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecMSCryptoX509IssuerSerialNodeRead	(xmlSecKeyDataPtr data,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecMSCryptoX509IssuerSerialNodeWrite	(PCCERT_CONTEXT cert,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecMSCryptoX509SKINodeRead		(xmlSecKeyDataPtr data,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecMSCryptoX509SKINodeWrite		(PCCERT_CONTEXT cert,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecMSCryptoX509CRLNodeRead		(xmlSecKeyDataPtr data,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecMSCryptoX509CRLNodeWrite		(PCCRL_CONTEXT crl,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecMSCryptoKeyDataX509VerifyAndExtractKey(xmlSecKeyDataPtr data, 
								xmlSecKeyPtr key,
								xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyDataPtr	xmlSecMSCryptoX509CertGetKey		(PCCERT_CONTEXT cert);
static PCCERT_CONTEXT	xmlSecMSCryptoX509CertDerRead		(const xmlSecByte* buf, 
								 xmlSecSize size);
static PCCERT_CONTEXT	xmlSecMSCryptoX509CertBase64DerRead	(xmlChar* buf);
static xmlChar*		xmlSecMSCryptoX509CertBase64DerWrite	(PCCERT_CONTEXT cert, 
								 int base64LineWrap);
static PCCRL_CONTEXT	xmlSecMSCryptoX509CrlDerRead		(xmlSecByte* buf, 
								 xmlSecSize size,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static PCCRL_CONTEXT xmlSecMSCryptoX509CrlBase64DerRead		(xmlChar* buf,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static xmlChar*		xmlSecMSCryptoX509CrlBase64DerWrite	(PCCRL_CONTEXT crl, 
								 int base64LineWrap);
static xmlChar*		xmlSecMSCryptoX509NameWrite(PCERT_NAME_BLOB nm);
static xmlChar*		xmlSecMSCryptoASN1IntegerWrite		(PCRYPT_INTEGER_BLOB num);
static xmlChar*		xmlSecMSCryptoX509SKIWrite		(PCCERT_CONTEXT cert);
static void		xmlSecMSCryptoX509CertDebugDump		(PCCERT_CONTEXT cert, 
								 FILE* output);
static void		xmlSecMSCryptoX509CertDebugXmlDump	(PCCERT_CONTEXT cert, 
								 FILE* output);
static int		xmlSecMSCryptoX509CertGetTime		(FILETIME t,
								 time_t* res);

/*************************************************************************
 *
 * Internal MSCrypto X509 data CTX
 *
 ************************************************************************/
typedef struct _xmlSecMSCryptoX509DataCtx	xmlSecMSCryptoX509DataCtx,
						*xmlSecMSCryptoX509DataCtxPtr;

struct _xmlSecMSCryptoX509DataCtx {
    PCCERT_CONTEXT  keyCert;

    HCERTSTORE hMemStore;
    unsigned int numCerts;
    unsigned int numCrls;
};

/**************************************************************************
 *
 * <dsig:X509Data> processing
 *
 *
 * The X509Data  Element (http://www.w3.org/TR/xmldsig-core/#sec-X509Data)
 *
 * An X509Data element within KeyInfo contains one or more identifiers of keys 
 * or X509 certificates (or certificates' identifiers or a revocation list). 
 * The content of X509Data is:
 *
 *  1. At least one element, from the following set of element types; any of these may appear together or more than once iff (if and only if) each instance describes or is related to the same certificate:
 *  2.
 *    * The X509IssuerSerial element, which contains an X.509 issuer 
 *	distinguished name/serial number pair that SHOULD be compliant 
 *	with RFC2253 [LDAP-DN],
 *    * The X509SubjectName element, which contains an X.509 subject 
 *	distinguished name that SHOULD be compliant with RFC2253 [LDAP-DN],
 *    * The X509SKI element, which contains the base64 encoded plain (i.e. 
 *	non-DER-encoded) value of a X509 V.3 SubjectKeyIdentifier extension.
 *    * The X509Certificate element, which contains a base64-encoded [X509v3] 
 *	certificate, and
 *    * Elements from an external namespace which accompanies/complements any 
 *	of the elements above.
 *    * The X509CRL element, which contains a base64-encoded certificate 
 *	revocation list (CRL) [X509v3].
 *
 * Any X509IssuerSerial, X509SKI, and X509SubjectName elements that appear 
 * MUST refer to the certificate or certificates containing the validation key.
 * All such elements that refer to a particular individual certificate MUST be 
 * grouped inside a single X509Data element and if the certificate to which 
 * they refer appears, it MUST also be in that X509Data element.
 *
 * Any X509IssuerSerial, X509SKI, and X509SubjectName elements that relate to 
 * the same key but different certificates MUST be grouped within a single 
 * KeyInfo but MAY occur in multiple X509Data elements.
 *
 * All certificates appearing in an X509Data element MUST relate to the 
 * validation key by either containing it or being part of a certification 
 * chain that terminates in a certificate containing the validation key.
 *
 * No ordering is implied by the above constraints.
 *
 * Note, there is no direct provision for a PKCS#7 encoded "bag" of 
 * certificates or CRLs. However, a set of certificates and CRLs can occur 
 * within an X509Data element and multiple X509Data elements can occur in a 
 * KeyInfo. Whenever multiple certificates occur in an X509Data element, at 
 * least one such certificate must contain the public key which verifies the 
 * signature.
 *
 * Schema Definition
 *
 *  <element name="X509Data" type="ds:X509DataType"/> 
 *  <complexType name="X509DataType">
 *    <sequence maxOccurs="unbounded">
 *      <choice>
 *        <element name="X509IssuerSerial" type="ds:X509IssuerSerialType"/>
 *        <element name="X509SKI" type="base64Binary"/>
 *        <element name="X509SubjectName" type="string"/>
 *        <element name="X509Certificate" type="base64Binary"/>
 *        <element name="X509CRL" type="base64Binary"/>
 *        <any namespace="##other" processContents="lax"/>
 *      </choice>
 *    </sequence>
 *  </complexType>
 *  <complexType name="X509IssuerSerialType"> 
 *    <sequence> 
 *       <element name="X509IssuerName" type="string"/> 
 *       <element name="X509SerialNumber" type="integer"/> 
 *     </sequence>
 *  </complexType>
 *
 *  DTD
 *
 *    <!ELEMENT X509Data ((X509IssuerSerial | X509SKI | X509SubjectName |
 *                          X509Certificate | X509CRL)+ %X509.ANY;)>
 *    <!ELEMENT X509IssuerSerial (X509IssuerName, X509SerialNumber) >
 *    <!ELEMENT X509IssuerName (#PCDATA) >
 *    <!ELEMENT X509SubjectName (#PCDATA) >
 *    <!ELEMENT X509SerialNumber (#PCDATA) >
 *    <!ELEMENT X509SKI (#PCDATA) >
 *    <!ELEMENT X509Certificate (#PCDATA) >
 *    <!ELEMENT X509CRL (#PCDATA) >
 *
 * -----------------------------------------------------------------------
 *
 * xmlSecMSCryptoX509DataCtx is located after xmlSecTransform
 *
 *************************************************************************/
#define xmlSecMSCryptoX509DataSize	\
    (sizeof(xmlSecKeyData) + sizeof(xmlSecMSCryptoX509DataCtx))	
#define xmlSecMSCryptoX509DataGetCtx(data) \
    ((xmlSecMSCryptoX509DataCtxPtr)(((xmlSecByte*)(data)) + sizeof(xmlSecKeyData)))

static int		xmlSecMSCryptoKeyDataX509Initialize	(xmlSecKeyDataPtr data);
static int		xmlSecMSCryptoKeyDataX509Duplicate	(xmlSecKeyDataPtr dst,
								 xmlSecKeyDataPtr src);
static void		xmlSecMSCryptoKeyDataX509Finalize	(xmlSecKeyDataPtr data);
static int		xmlSecMSCryptoKeyDataX509XmlRead	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecMSCryptoKeyDataX509XmlWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static xmlSecKeyDataType xmlSecMSCryptoKeyDataX509GetType	(xmlSecKeyDataPtr data);
static const xmlChar* xmlSecMSCryptoKeyDataX509GetIdentifier	(xmlSecKeyDataPtr data);

static void		xmlSecMSCryptoKeyDataX509DebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecMSCryptoKeyDataX509DebugXmlDump(xmlSecKeyDataPtr data,
							      FILE* output);



static xmlSecKeyDataKlass xmlSecMSCryptoKeyDataX509Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCryptoX509DataSize,

    /* data */
    xmlSecNameX509Data,
    xmlSecKeyDataUsageKeyInfoNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefX509Data,				/* const xmlChar* href; */
    xmlSecNodeX509Data,				/* const xmlChar* dataNodeName; */
    xmlSecDSigNs,				/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecMSCryptoKeyDataX509Initialize,	/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCryptoKeyDataX509Duplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCryptoKeyDataX509Finalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,					/* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecMSCryptoKeyDataX509GetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    NULL,					/* xmlSecKeyDataGetSizeMethod getSize; */
    xmlSecMSCryptoKeyDataX509GetIdentifier,	/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    xmlSecMSCryptoKeyDataX509XmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecMSCryptoKeyDataX509XmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,					/* xmlSecKeyDataBinReadMethod binRead; */
    NULL,					/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCryptoKeyDataX509DebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCryptoKeyDataX509DebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecMSCryptoKeyDataX509GetKlass:
 * 
 * The MSCrypto X509 key data klass (http://www.w3.org/TR/xmldsig-core/#sec-X509Data).
 *
 * Returns the X509 data klass.
 */
xmlSecKeyDataId 
xmlSecMSCryptoKeyDataX509GetKlass(void) {
    return(&xmlSecMSCryptoKeyDataX509Klass);
}

/**
 * xmlSecMSCryptoKeyDataX509GetKeyCert:
 * @data:		the pointer to X509 key data.
 *
 * Gets the certificate from which the key was extracted. 
 *
 * Returns the key's certificate or NULL if key data was not used for key
 * extraction or an error occurs.
 */
PCCERT_CONTEXT
xmlSecMSCryptoKeyDataX509GetKeyCert(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoX509DataCtxPtr ctx;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), NULL);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->keyCert);
}

/**
 * xmlSecMSCryptoKeyDataX509AdoptKeyCert:
 * @data:		the pointer to X509 key data.
 * @cert:		the pointer to MSCRYPTO X509 certificate.
 *
 * Sets the key's certificate in @data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoKeyDataX509AdoptKeyCert(xmlSecKeyDataPtr data, PCCERT_CONTEXT cert) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    
    if(ctx->keyCert != NULL) {
	CertFreeCertificateContext(ctx->keyCert);
    }
    ctx->keyCert = cert;

    return(0);
}

/**
 * xmlSecMSCryptoKeyDataX509AdoptCert:
 * @data:		the pointer to X509 key data.
 * @cert:		the pointer to MSCRYPTO X509 certificate.
 *
 * Adds certificate to the X509 key data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecMSCryptoKeyDataX509AdoptCert(xmlSecKeyDataPtr data, PCCERT_CONTEXT cert) {
    xmlSecMSCryptoX509DataCtxPtr ctx;
    PCCERT_CONTEXT pCert;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    pCert = CertDuplicateCertificateContext(cert);
    CertFreeCertificateContext(cert);
    if (!pCert) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "CertDuplicateCertificateContext",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    if (ctx->hMemStore == 0) {
	ctx->hMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
				       0, 
				       0, 
				       CERT_STORE_CREATE_NEW_FLAG, 
				       NULL);
	if (ctx->hMemStore == 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			"CertOpenStore",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }

    if (!CertAddCertificateContextToStore(ctx->hMemStore, pCert, CERT_STORE_ADD_ALWAYS, NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "CertAddCertificateContextToStore",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }
    ctx->numCerts++;
      
    return(0);
}

/**
 * xmlSecMSCryptoKeyDataX509GetCert:
 * @data:		the pointer to X509 key data.
 * @pos:		the desired certificate position.
 * 
 * Gets a certificate from X509 key data.
 *
 * Returns the pointer to certificate or NULL if @pos is larger than the 
 * number of certificates in @data or an error occurs.
 */
PCCERT_CONTEXT 
xmlSecMSCryptoKeyDataX509GetCert(xmlSecKeyDataPtr data, xmlSecSize pos) {
    xmlSecMSCryptoX509DataCtxPtr ctx;
    PCCERT_CONTEXT pCert = NULL;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), NULL);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    while ((pCert = CertEnumCertificatesInStore(ctx->hMemStore, pCert)) && (pos > 0)) {
	pos--;
    }

    return pCert;
}

/**
 * xmlSecMSCryptoKeyDataX509GetCertsSize:
 * @data:		the pointer to X509 key data.
 *
 * Gets the number of certificates in @data.
 *
 * Returns te number of certificates in @data.
 */
xmlSecSize 	
xmlSecMSCryptoKeyDataX509GetCertsSize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), 0);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return (ctx->numCerts);
}

/**
 * xmlSecMSCryptoKeyDataX509AdoptCrl:
 * @data:		the pointer to X509 key data.
 * @crl:		the pointer to MSCrypto X509 CRL.
 *
 * Adds CRL to the X509 key data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecMSCryptoKeyDataX509AdoptCrl(xmlSecKeyDataPtr data, PCCRL_CONTEXT crl) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(crl != 0, -1);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    if (ctx->hMemStore == 0) {
	ctx->hMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
				       0, 
				       0, 
				       CERT_STORE_CREATE_NEW_FLAG, 
				       NULL);
	if (ctx->hMemStore == 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			"CertOpenStore",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }

    if (!CertAddCRLContextToStore(ctx->hMemStore, crl, CERT_STORE_ADD_ALWAYS, NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "CertAddCRLContextToStore",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }
    ctx->numCrls++;

    return(0);
}

/**
 * xmlSecMSCryptoKeyDataX509GetCrl:
 * @data:               the pointer to X509 key data.
 * @pos:                the desired CRL position.
 *
 * Gets a CRL from X509 key data.
 *
 * Returns the pointer to CRL or NULL if @pos is larger than the
 * number of CRLs in @data or an error occurs.
 */
PCCRL_CONTEXT
xmlSecMSCryptoKeyDataX509GetCrl(xmlSecKeyDataPtr data, xmlSecSize pos) {
    xmlSecMSCryptoX509DataCtxPtr ctx;
    PCCRL_CONTEXT pCRL = NULL;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), NULL);
    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    xmlSecAssert2(ctx->hMemStore != 0, NULL);
    xmlSecAssert2(pos < ctx->numCrls, NULL);

    while ((pCRL = CertEnumCRLsInStore(ctx->hMemStore, pCRL)) && (pos > 0)) {
	pos--;
    }

    return pCRL;
}

/**
 * xmlSecMSCryptoKeyDataX509GetCrlsSize:
 * @data:               the pointer to X509 key data.
 *
 * Gets the number of CRLs in @data.
 *
 * Returns te number of CRLs in @data.
 */
xmlSecSize
xmlSecMSCryptoKeyDataX509GetCrlsSize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), 0);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return(ctx->numCrls);
}

static int	
xmlSecMSCryptoKeyDataX509Initialize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCryptoX509DataCtx));
    return(0);
}

static int
xmlSecMSCryptoKeyDataX509Duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    PCCERT_CONTEXT certSrc, certDst;
    PCCRL_CONTEXT crlSrc, crlDst;
    xmlSecSize size, pos;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCryptoKeyDataX509Id), -1);

    /* copy certsList */ 
    size = xmlSecMSCryptoKeyDataX509GetCertsSize(src);
    for(pos = 0; pos < size; ++pos) {
	/* TBD: function below does linear scan, eliminate loop within
	* loop
	*/
	certSrc = xmlSecMSCryptoKeyDataX509GetCert(src, pos);
	if(certSrc == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(src)),
			"xmlSecMSCryptoKeyDataX509GetCert",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"pos=%d", pos);
	    return(-1);
	}

	certDst = CertDuplicateCertificateContext(certSrc);
	if(certDst == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"CertDuplicateCertificateContext",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}

	ret = xmlSecMSCryptoKeyDataX509AdoptCert(dst, certDst);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"xmlSecMSCryptoKeyDataX509AdoptCert",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    CertFreeCertificateContext(certDst);
	    return(-1);
	}
    }

    /* copy crls */
    size = xmlSecMSCryptoKeyDataX509GetCrlsSize(src);
    for(pos = 0; pos < size; ++pos) {
	crlSrc = xmlSecMSCryptoKeyDataX509GetCrl(src, pos);
	if(crlSrc == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(src)),
			"xmlSecMSCryptoKeyDataX509GetCrl",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"pos=%d", pos);
	    return(-1);
	}

	crlDst = CertDuplicateCRLContext(crlSrc);
	if(crlDst == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"CertDuplicateCRLContext",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}

	ret = xmlSecMSCryptoKeyDataX509AdoptCrl(dst, crlDst);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"xmlSecMSCryptoKeyDataX509AdoptCrl",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    CertFreeCRLContext(crlDst);
	    return(-1);
	}
    }

    /* copy key cert if exist */
    certSrc = xmlSecMSCryptoKeyDataX509GetKeyCert(src);
    if(certSrc != NULL) {
	certDst = CertDuplicateCertificateContext(certSrc);
	if(certDst == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"CertDuplicateCertificateContext",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	ret = xmlSecMSCryptoKeyDataX509AdoptKeyCert(dst, certDst);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"xmlSecMSCryptoKeyDataX509AdoptKeyCert",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    CertFreeCertificateContext(certDst);
	    return(-1);
	}
    }
    return(0);
}

static void
xmlSecMSCryptoKeyDataX509Finalize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id));

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    if(ctx->keyCert != NULL) {
	CertFreeCertificateContext(ctx->keyCert);
	ctx->keyCert = NULL;
    }

    if (ctx->hMemStore) {
	if (!CertCloseStore(ctx->hMemStore, CERT_CLOSE_STORE_FORCE_FLAG)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"CertCloseStore",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return;
	}
    }

    memset(ctx, 0, sizeof(xmlSecMSCryptoX509DataCtx));
}

static int
xmlSecMSCryptoKeyDataX509XmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    int ret;

    xmlSecAssert2(id == xmlSecMSCryptoKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    data = xmlSecKeyEnsureData(key, id);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecKeyEnsureData",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    ret = xmlSecMSCryptoX509DataNodeRead(data, node, keyInfoCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecMSCryptoX509DataNodeRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS) == 0) {
	ret = xmlSecMSCryptoKeyDataX509VerifyAndExtractKey(data, key, keyInfoCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecMSCryptoKeyDataX509VerifyAndExtractKey",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }
    return(0);
}

static int 
xmlSecMSCryptoKeyDataX509XmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    PCCERT_CONTEXT cert;
    PCCRL_CONTEXT crl;
    xmlSecSize size, pos;
    int content = 0;
    int ret;
    				
    xmlSecAssert2(id == xmlSecMSCryptoKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    content = xmlSecX509DataGetNodeContent (node, 1, keyInfoCtx);
    if (content < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecX509DataGetNodeContent",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "content=%d", content);
	return(-1);
    } else if(content == 0) {
	/* by default we are writing certificates and crls */
	content = XMLSEC_X509DATA_DEFAULT;
    }

    /* get x509 data */
    data = xmlSecKeyGetData(key, id);
    if(data == NULL) {
	/* no x509 data in the key */
	return(0);	
    }

    /* write certs */
    size = xmlSecMSCryptoKeyDataX509GetCertsSize(data);
    for(pos = 0; pos < size; ++pos) {
	cert = xmlSecMSCryptoKeyDataX509GetCert(data, pos);
	if(cert == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecMSCryptoKeyDataX509GetCert",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"pos=%d", pos);
	    return(-1);
	}

	if((content & XMLSEC_X509DATA_CERTIFICATE_NODE) != 0) {
	    ret = xmlSecMSCryptoX509CertificateNodeWrite(cert, node, keyInfoCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			    "xmlSecMSCryptoX509CertificateNodeWrite",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "pos=%d", pos);
		return(-1);
	    }
	}

	if((content & XMLSEC_X509DATA_SUBJECTNAME_NODE) != 0) {
	    ret = xmlSecMSCryptoX509SubjectNameNodeWrite(cert, node, keyInfoCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			    "xmlSecMSCryptoX509SubjectNameNodeWrite",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "pos=%d", pos);
		return(-1);
	    }
	}

	if((content & XMLSEC_X509DATA_ISSUERSERIAL_NODE) != 0) {
	    ret = xmlSecMSCryptoX509IssuerSerialNodeWrite(cert, node, keyInfoCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			    "xmlSecMSCryptoX509IssuerSerialNodeWrite",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "pos=%d", pos);
		return(-1);
	    }
	}

	if((content & XMLSEC_X509DATA_SKI_NODE) != 0) {
	    ret = xmlSecMSCryptoX509SKINodeWrite(cert, node, keyInfoCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			    "xmlSecMSCryptoX509SKINodeWrite",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "pos=%d", pos);
		return(-1);
	    }
	}
    }    

    /* write crls if needed */
    if((content & XMLSEC_X509DATA_CRL_NODE) != 0) {
	size = xmlSecMSCryptoKeyDataX509GetCrlsSize(data);
	for(pos = 0; pos < size; ++pos) {
	    crl = xmlSecMSCryptoKeyDataX509GetCrl(data, pos);
	    if(crl == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			    "xmlSecMSCryptoKeyDataX509GetCrl",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "pos=%d", pos);
		return(-1);
	    }

	    ret = xmlSecMSCryptoX509CRLNodeWrite(crl, node, keyInfoCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			    "xmlSecMSCryptoX509CRLNodeWrite",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "pos=%d", pos);
		return(-1);
	    }
	}
    }

    return(0);
}

static xmlSecKeyDataType
xmlSecMSCryptoKeyDataX509GetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), xmlSecKeyDataTypeUnknown);

    /* TODO: return verified/not verified status */     
    return(xmlSecKeyDataTypeUnknown);
}

static const xmlChar*
xmlSecMSCryptoKeyDataX509GetIdentifier(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), NULL);
    
    /* TODO */    
    return(NULL);
}

static void 
xmlSecMSCryptoKeyDataX509DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    PCCERT_CONTEXT cert;
    xmlSecSize size, pos;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== X509 Data:\n");
    cert = xmlSecMSCryptoKeyDataX509GetKeyCert(data);
    if(cert != NULL) {
	fprintf(output, "==== Key Certificate:\n");
	xmlSecMSCryptoX509CertDebugDump(cert, output);
    }

    size = xmlSecMSCryptoKeyDataX509GetCertsSize(data);
    for(pos = 0; pos < size; ++pos) {
	cert = xmlSecMSCryptoKeyDataX509GetCert(data, pos);
	if(cert == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			"xmlSecMSCryptoKeyDataX509GetCert",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"pos=%d", pos);
	    return;
	}
	fprintf(output, "==== Certificate:\n");
	xmlSecMSCryptoX509CertDebugDump(cert, output);
    }

    /* we don't print out crls */
}

static void
xmlSecMSCryptoKeyDataX509DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    PCCERT_CONTEXT cert;
    xmlSecSize size, pos;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<X509Data>\n");
    cert = xmlSecMSCryptoKeyDataX509GetKeyCert(data);
    if(cert != NULL) {
	fprintf(output, "<KeyCertificate>\n");
	xmlSecMSCryptoX509CertDebugXmlDump(cert, output);
	fprintf(output, "</KeyCertificate>\n");
    }

    size = xmlSecMSCryptoKeyDataX509GetCertsSize(data);
    for(pos = 0; pos < size; ++pos) {
	cert = xmlSecMSCryptoKeyDataX509GetCert(data, pos);
	if(cert == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			"xmlSecMSCryptoKeyDataX509GetCert",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"pos=%d", pos);
	    return;
	}
	fprintf(output, "<Certificate>\n");
	xmlSecMSCryptoX509CertDebugXmlDump(cert, output);
	fprintf(output, "</Certificate>\n");
    }

    /* we don't print out crls */
    fprintf(output, "</X509Data>\n");
}

static int
xmlSecMSCryptoX509DataNodeRead(xmlSecKeyDataPtr data, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlNodePtr cur; 
    int ret;
        
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    
    for(cur = xmlSecGetNextElementNode(node->children);
	cur != NULL;
	cur = xmlSecGetNextElementNode(cur->next)) {

	ret = 0;
	if(xmlSecCheckNodeName(cur, xmlSecNodeX509Certificate, xmlSecDSigNs)) {
	    ret = xmlSecMSCryptoX509CertificateNodeRead(data, cur, keyInfoCtx);
	} else if(xmlSecCheckNodeName(cur, xmlSecNodeX509SubjectName, xmlSecDSigNs)) {
	    ret = xmlSecMSCryptoX509SubjectNameNodeRead(data, cur, keyInfoCtx);
	} else if(xmlSecCheckNodeName(cur, xmlSecNodeX509IssuerSerial, xmlSecDSigNs)) {
	    ret = xmlSecMSCryptoX509IssuerSerialNodeRead(data, cur, keyInfoCtx);
	} else if(xmlSecCheckNodeName(cur, xmlSecNodeX509SKI, xmlSecDSigNs)) {
	    ret = xmlSecMSCryptoX509SKINodeRead(data, cur, keyInfoCtx);
	} else if(xmlSecCheckNodeName(cur, xmlSecNodeX509CRL, xmlSecDSigNs)) {
	    ret = xmlSecMSCryptoX509CRLNodeRead(data, cur, keyInfoCtx);
	} else if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CHILD) != 0) {
	    /* laxi schema validation: ignore unknown nodes */
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
			XMLSEC_ERRORS_R_UNEXPECTED_NODE,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		XMLSEC_ERRORS_R_XMLSEC_FAILED,
		"read node failed");
	    return(-1);  
	}	
    }
    return(0);
}

static int
xmlSecMSCryptoX509CertificateNodeRead(xmlSecKeyDataPtr data, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {	
    xmlChar *content;
    PCCERT_CONTEXT cert;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    content = xmlNodeGetContent(node);
    if((content == NULL) || (xmlSecIsEmptyString(content) == 1)) {
	if(content != NULL) {
	    xmlFree(content);
	}
	if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_STOP_ON_EMPTY_NODE) != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			xmlSecErrorsSafeString(xmlSecNodeGetName(node)),
			XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	return(0);
    }

    cert = xmlSecMSCryptoX509CertBase64DerRead(content);
    if(cert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecMSCryptoX509CertBase64DerRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFree(content);
	return(-1);
    }    

    ret = xmlSecMSCryptoKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecMSCryptoKeyDataX509AdoptCert",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	CertFreeCertificateContext(cert);
	xmlFree(content);
	return(-1);
    }
     
    xmlFree(content);
    return(0);
}

static int 
xmlSecMSCryptoX509CertificateNodeWrite(PCCERT_CONTEXT cert, xmlNodePtr node, 
				       xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlChar* buf;
    xmlNodePtr cur;
    
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    
    /* set base64 lines size from context */
    buf = xmlSecMSCryptoX509CertBase64DerWrite(cert, keyInfoCtx->base64LineSize); 
    if(buf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoX509CertBase64DerWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    cur = xmlSecAddChild(node, xmlSecNodeX509Certificate, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeX509Certificate));
	xmlFree(buf);
	return(-1);	
    }

    /* todo: add \n around base64 data - from context */
    /* todo: add errors check */
    xmlNodeSetContent(cur, xmlSecStringCR);
    xmlNodeSetContent(cur, buf);
    xmlFree(buf);
    return(0);
}

static int		
xmlSecMSCryptoX509SubjectNameNodeRead(xmlSecKeyDataPtr data, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {	
    xmlSecKeyDataStorePtr x509Store;
    xmlChar* subject;
    PCCERT_CONTEXT cert;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecMSCryptoX509StoreId);
    if(x509Store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecKeysMngrGetDataStore",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    subject = xmlNodeGetContent(node);
    if((subject == NULL) || (xmlSecIsEmptyString(subject) == 1)) {
	if(subject != NULL) {
	    xmlFree(subject);
	}
	if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_STOP_ON_EMPTY_NODE) != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			xmlSecErrorsSafeString(xmlSecNodeGetName(node)),
			XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	return(0);
    }

    cert = xmlSecMSCryptoX509StoreFindCert(x509Store, subject, NULL, NULL, NULL, keyInfoCtx);
    if(cert == NULL){
	xmlFree(subject);

	if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CERT) != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			NULL,
			XMLSEC_ERRORS_R_CERT_NOT_FOUND,
			"subject=%s", 
			xmlSecErrorsSafeString(subject));
	    return(-1);
	}
	return(0);
    }

    ret = xmlSecMSCryptoKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecMSCryptoKeyDataX509AdoptCert",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	CertFreeCertificateContext(cert);
	xmlFree(subject);
	return(-1);
    }

    xmlFree(subject);
    return(0);
}

static int
xmlSecMSCryptoX509SubjectNameNodeWrite(PCCERT_CONTEXT cert, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx ATTRIBUTE_UNUSED) {
    xmlChar* buf = NULL;
    xmlNodePtr cur = NULL;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    buf = xmlSecMSCryptoX509NameWrite(&(cert->pCertInfo->Subject));
    if(buf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoX509NameWrite(&(cert->pCertInfo->Subject))",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    cur = xmlSecAddChild(node, xmlSecNodeX509SubjectName, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeX509SubjectName));
	xmlFree(buf);
	return(-1);
    }
    xmlNodeSetContent(cur, buf);
    xmlFree(buf);
    return(0);
}

static int 
xmlSecMSCryptoX509IssuerSerialNodeRead(xmlSecKeyDataPtr data, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataStorePtr x509Store;
    xmlNodePtr cur;
    xmlChar *issuerName;
    xmlChar *issuerSerial;    
    PCCERT_CONTEXT cert;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecMSCryptoX509StoreId);
    if(x509Store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecKeysMngrGetDataStore",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    cur = xmlSecGetNextElementNode(node->children);
    if(cur == NULL) {
	if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_STOP_ON_EMPTY_NODE) != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			xmlSecErrorsSafeString(xmlSecNodeX509IssuerName),
			XMLSEC_ERRORS_R_NODE_NOT_FOUND,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(cur)));
	    return(-1);
	}
	return(0);
    }

    /* the first is required node X509IssuerName */
    if(!xmlSecCheckNodeName(cur, xmlSecNodeX509IssuerName, xmlSecDSigNs)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    xmlSecErrorsSafeString(xmlSecNodeX509IssuerName),
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)));
	return(-1);
    }    
    issuerName = xmlNodeGetContent(cur);
    if(issuerName == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeX509IssuerName));
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next); 

    /* next is required node X509SerialNumber */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, xmlSecNodeX509SerialNumber, xmlSecDSigNs)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeX509SerialNumber));
	xmlFree(issuerName);
	return(-1);
    }    
    issuerSerial = xmlNodeGetContent(cur);
    if(issuerSerial == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    xmlSecErrorsSafeString(xmlSecNodeX509SerialNumber),
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)));
	xmlFree(issuerName);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next); 

    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFree(issuerSerial);
	xmlFree(issuerName);
	return(-1);
    }

    cert = xmlSecMSCryptoX509StoreFindCert(x509Store, NULL, issuerName, issuerSerial, NULL, keyInfoCtx);
    if(cert == NULL){
	xmlFree(issuerSerial);
	xmlFree(issuerName);

	if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CERT) != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			NULL,
			XMLSEC_ERRORS_R_CERT_NOT_FOUND,
			"issuerName=%s;issuerSerial=%s",
			xmlSecErrorsSafeString(issuerName), 
			xmlSecErrorsSafeString(issuerSerial));
	    return(-1);
	}
	return(0);    
    }

    ret = xmlSecMSCryptoKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecMSCryptoKeyDataX509AdoptCert",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	CertFreeCertificateContext(cert);
	xmlFree(issuerSerial);
	xmlFree(issuerName);
	return(-1);
    }
    
    xmlFree(issuerSerial);
    xmlFree(issuerName);
    return(0);
}

static int
xmlSecMSCryptoX509IssuerSerialNodeWrite(PCCERT_CONTEXT cert, 
					xmlNodePtr node, 
					xmlSecKeyInfoCtxPtr keyInfoCtx ATTRIBUTE_UNUSED) {
    xmlNodePtr cur;
    xmlNodePtr issuerNameNode;
    xmlNodePtr issuerNumberNode;
    xmlChar* buf;
    
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* create xml nodes */
    cur = xmlSecAddChild(node, xmlSecNodeX509IssuerSerial, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeX509IssuerSerial));
	return(-1);
    }

    issuerNameNode = xmlSecAddChild(cur, xmlSecNodeX509IssuerName, xmlSecDSigNs);
    if(issuerNameNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeX509IssuerName));
	return(-1);
    }

    issuerNumberNode = xmlSecAddChild(cur, xmlSecNodeX509SerialNumber, xmlSecDSigNs);
    if(issuerNumberNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeX509SerialNumber));
	return(-1);
    }

    /* write data */
    buf = xmlSecMSCryptoX509NameWrite(&(cert->pCertInfo->Issuer));
    if(buf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoX509NameWrite(&(cert->pCertInfo->Issuer))",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    xmlNodeSetContent(issuerNameNode, buf);
    xmlFree(buf);

    buf = xmlSecMSCryptoASN1IntegerWrite(&(cert->pCertInfo->SerialNumber));
    if(buf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoASN1IntegerWrite(&(cert->serialNumber))",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    xmlNodeSetContent(issuerNumberNode, buf);
    xmlFree(buf);

    return(0);
}

static int 
xmlSecMSCryptoX509SKINodeRead(xmlSecKeyDataPtr data, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataStorePtr x509Store;
    xmlChar* ski;
    PCCERT_CONTEXT cert;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecMSCryptoX509StoreId);
    if(x509Store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecKeysMngrGetDataStore",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    ski = xmlNodeGetContent(node);
    if((ski == NULL) || (xmlSecIsEmptyString(ski) == 1)) {
	if(ski != NULL) {
	    xmlFree(ski);
	}
	if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_STOP_ON_EMPTY_NODE) != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			xmlSecErrorsSafeString(xmlSecNodeGetName(node)),
			XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeX509SKI));
	    return(-1);
	}
	return(0);
    }

    cert = xmlSecMSCryptoX509StoreFindCert(x509Store, NULL, NULL, NULL, ski, keyInfoCtx);
    if(cert == NULL){
	xmlFree(ski);

	if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CERT) != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			NULL,
			XMLSEC_ERRORS_R_CERT_NOT_FOUND,
			"ski=%s", 
			xmlSecErrorsSafeString(ski));
	    return(-1);
	}
	return(0);
    }

    ret = xmlSecMSCryptoKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecMSCryptoKeyDataX509AdoptCert",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	CertFreeCertificateContext(cert);
	xmlFree(ski);
	return(-1);
    }

    xmlFree(ski);
    return(0);
}

static int
xmlSecMSCryptoX509SKINodeWrite(PCCERT_CONTEXT cert, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx ATTRIBUTE_UNUSED) {
    xmlChar *buf = NULL;
    xmlNodePtr cur = NULL;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    buf = xmlSecMSCryptoX509SKIWrite(cert);
    if(buf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoX509SKIWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    cur = xmlSecAddChild(node, xmlSecNodeX509SKI, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "new_node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeX509SKI));
	xmlFree(buf);
	return(-1);
    }
    xmlNodeSetContent(cur, buf);
    xmlFree(buf);

    return(0);
}

static int 
xmlSecMSCryptoX509CRLNodeRead(xmlSecKeyDataPtr data, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlChar *content;
    PCCRL_CONTEXT crl;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    content = xmlNodeGetContent(node);
    if((content == NULL) || (xmlSecIsEmptyString(content) == 1)) {
	if(content != NULL) {
	    xmlFree(content);
	}
	if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_STOP_ON_EMPTY_NODE) != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			xmlSecErrorsSafeString(xmlSecNodeGetName(node)),
			XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	return(0);
    }

    crl = xmlSecMSCryptoX509CrlBase64DerRead(content, keyInfoCtx);
    if(crl == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecMSCryptoX509CrlBase64DerRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFree(content);
	return(-1);
    }    

    if (0 != xmlSecMSCryptoKeyDataX509AdoptCrl(data, crl)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecMSCryptoKeyDataX509AdoptCrl",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFree(content);
    CertFreeCRLContext(crl); 
	return(-1);
    }
    
    xmlFree(content);
    return(0);
}

static int
xmlSecMSCryptoX509CRLNodeWrite(PCCRL_CONTEXT crl, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlChar* buf = NULL;
    xmlNodePtr cur = NULL;

    xmlSecAssert2(crl != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* set base64 lines size from context */
    buf = xmlSecMSCryptoX509CrlBase64DerWrite(crl, keyInfoCtx->base64LineSize); 
    if(buf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoX509CrlBase64DerWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    cur = xmlSecAddChild(node, xmlSecNodeX509CRL, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "new_node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeX509CRL));
	xmlFree(buf);
	return(-1);
    }
    /* todo: add \n around base64 data - from context */
    /* todo: add errors check */
    xmlNodeSetContent(cur, xmlSecStringCR);
    xmlNodeSetContent(cur, buf);
    xmlFree(buf);

    return(0);
}


static int
xmlSecMSCryptoKeyDataX509VerifyAndExtractKey(xmlSecKeyDataPtr data, xmlSecKeyPtr key,
					     xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCryptoX509DataCtxPtr ctx;
    xmlSecKeyDataStorePtr x509Store;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecMSCryptoX509StoreId);
    if(x509Store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecKeysMngrGetDataStore",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    if((ctx->keyCert == NULL) && (ctx->hMemStore != 0) && (xmlSecKeyGetValue(key) == NULL)) {
	PCCERT_CONTEXT cert;

	cert = xmlSecMSCryptoX509StoreVerify(x509Store, ctx->hMemStore, keyInfoCtx);
	if(cert != NULL) {
	    xmlSecKeyDataPtr keyValue;

	    ctx->keyCert = CertDuplicateCertificateContext(cert);
	    if(ctx->keyCert == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			    "CertDuplicateCertificateContext",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }

	    keyValue = xmlSecMSCryptoX509CertGetKey(ctx->keyCert);
	    if(keyValue == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			    "xmlSecMSCryptoX509CertGetKey",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }

	    /* verify that the key matches our expectations */
	    if(xmlSecKeyReqMatchKeyValue(&(keyInfoCtx->keyReq), keyValue) != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			    "xmlSecKeyReqMatchKeyValue",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		xmlSecKeyDataDestroy(keyValue);
		return(-1);
	    }	

	    ret = xmlSecKeySetValue(key, keyValue);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			    "xmlSecKeySetValue",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		xmlSecKeyDataDestroy(keyValue);
		return(-1);
	    }	    

	    ret = xmlSecMSCryptoX509CertGetTime(ctx->keyCert->pCertInfo->NotBefore, &(key->notValidBefore));
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			    "xmlSecMSCryptoX509CertGetTime",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "notValidBefore");
		return(-1);
	    }
	    ret = xmlSecMSCryptoX509CertGetTime(ctx->keyCert->pCertInfo->NotAfter, &(key->notValidAfter));
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			    "xmlSecMSCryptoX509CertGetTime",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "notValidAfter");
		return(-1);
	    }

	} else if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_INVALID_CERT) != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			NULL,
			XMLSEC_ERRORS_R_CERT_NOT_FOUND,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }
    return(0);
}

static int
xmlSecMSCryptoX509CertGetTime(FILETIME t, time_t* res) {
    LONGLONG result;
    result = t.dwHighDateTime;
    result = (result) << 32;
    result |= t.dwLowDateTime;
    result /= 10000;    /* Convert from 100 nano-sec periods to seconds. */
    result -= 11644473600000;  /* Convert from Windows epoch to Unix epoch */

    (*res) = (time_t)result;

    return(0);
}

static xmlSecKeyDataPtr	
xmlSecMSCryptoX509CertGetKey(PCCERT_CONTEXT cert) {
    xmlSecKeyDataPtr data;
    PCCERT_CONTEXT pCert = NULL;

    xmlSecAssert2(cert != NULL, NULL);

    pCert = CertDuplicateCertificateContext(cert);
    if(pCert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "CertDuplicateCertificateContext",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }    

    data = xmlSecMSCryptoCertAdopt(pCert, xmlSecKeyDataTypePublic);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoCertAdopt",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	CertFreeCertificateContext(pCert);
	return(NULL);	    
    }    

    return(data);
}

static PCCERT_CONTEXT
xmlSecMSCryptoX509CertBase64DerRead(xmlChar* buf) {
    int ret;

    xmlSecAssert2(buf != NULL, NULL);
    
    /* usual trick with base64 decoding "in-place" */
    ret = xmlSecBase64Decode(buf, (xmlSecByte*)buf, xmlStrlen(buf)); 
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBase64Decode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }
    
    return(xmlSecMSCryptoX509CertDerRead((xmlSecByte*)buf, ret));
}


static PCCERT_CONTEXT
xmlSecMSCryptoX509CertDerRead(const xmlSecByte* buf, xmlSecSize size) {
    PCCERT_CONTEXT cert;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);

    cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, buf, size);
    if(cert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "CertCreateCertificateContext",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }

    return(cert);
}

static xmlChar*
xmlSecMSCryptoX509CertBase64DerWrite(PCCERT_CONTEXT cert, int base64LineWrap) {
    xmlChar *res = NULL;
    xmlSecByte *p = NULL;
    long size;

    xmlSecAssert2(cert != NULL, NULL);

    p = cert->pbCertEncoded;
    size = cert->cbCertEncoded;
    if((size <= 0) || (p == NULL)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "cert->pbCertEncoded",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }

    res = xmlSecBase64Encode(p, size, base64LineWrap);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBase64Encode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }    

    return(res);
}

static PCCRL_CONTEXT
xmlSecMSCryptoX509CrlBase64DerRead(xmlChar* buf, 
				   xmlSecKeyInfoCtxPtr keyInfoCtx) {
    int ret;

    xmlSecAssert2(buf != NULL, NULL);

    /* usual trick with base64 decoding "in-place" */
    ret = xmlSecBase64Decode(buf, (xmlSecByte*)buf, xmlStrlen(buf)); 
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBase64Decode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }

    return(xmlSecMSCryptoX509CrlDerRead((xmlSecByte*)buf, ret, keyInfoCtx));
}


static PCCRL_CONTEXT			  
xmlSecMSCryptoX509CrlDerRead(xmlSecByte* buf, xmlSecSize size,
			     xmlSecKeyInfoCtxPtr keyInfoCtx) {
    PCCRL_CONTEXT crl = NULL;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);

    crl = CertCreateCRLContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, buf, size);

    if(crl == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "CertCreateCRLContext",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }

    return(crl);
			     }

static xmlChar*
xmlSecMSCryptoX509CrlBase64DerWrite(PCCRL_CONTEXT crl, int base64LineWrap) {
    xmlChar *res = NULL;
    xmlSecByte *p = NULL;
    long size;

    xmlSecAssert2(crl != NULL, NULL);

    p = crl->pbCrlEncoded;
    size = crl->cbCrlEncoded;
    if((size <= 0) || (p == NULL)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "crl->pbCrlEncoded",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }

    res = xmlSecBase64Encode(p, size, base64LineWrap);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBase64Encode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }   

    return(res);
}

static xmlChar*
xmlSecMSCryptoX509NameWrite(PCERT_NAME_BLOB nm) {
    xmlChar *res = NULL;
    char *str;
    DWORD csz;


    xmlSecAssert2(nm->pbData != NULL, NULL);
    xmlSecAssert2(nm->cbData > 0, NULL);

    csz = CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, nm, CERT_X500_NAME_STR, NULL, 0);
    str = (char *)malloc(csz);
    if (NULL == str) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "malloc",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return (NULL);
    }

    csz = CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, nm, CERT_X500_NAME_STR, str, csz);
    if (csz < 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "CertNameToStr",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	free(str);
	return(NULL);
    }

    res = xmlStrdup(BAD_CAST str);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlStrdup",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	free(str);
	return(NULL);
    }

    free(str);
    return(res);
}

static BOOL 
IsHexDigit(char c) {
    switch (c) {
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	case '0':
	case 'A':
	case 'B':
	case 'C':
	case 'D':
	case 'E':
	case 'F':
	case 'a':
	case 'b':
	case 'c':
	case 'd':
	case 'e':
	case 'f':
	    return TRUE;
	    break;
	default:
	    return FALSE;
    }
}

static xmlChar*
xmlSecMSCryptoASN1IntegerWrite(PCRYPT_INTEGER_BLOB num) {
    xmlChar *res;

    xmlSecAssert2(num != NULL, NULL);

    res = xmlSecBinaryToHexString(num->pbData, num->cbData, 0);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBinaryToHexString",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }

    return(res);
}

static xmlChar*
xmlSecMSCryptoX509SKIWrite(PCCERT_CONTEXT cert) {
    xmlChar *res = NULL;
    DWORD id = 0;
    DWORD dwSize;
    BYTE *bSKI = NULL;
    PCERT_EXTENSION pCertExt;

    xmlSecAssert2(cert != NULL, NULL);

    /* First check if the SKI extension actually exists, otherwise we get a SHA1 hash o fthe key/cert */
    pCertExt = CertFindExtension(szOID_SUBJECT_KEY_IDENTIFIER, cert->pCertInfo->cExtension, cert->pCertInfo->rgExtension);
    if (pCertExt == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
		    "CertFindExtension",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
		return (NULL);
	    }

    if (!CertGetCertificateContextProperty(cert, CERT_KEY_IDENTIFIER_PROP_ID, NULL, &dwSize) || dwSize < 1) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
		    "CertGetCertificateContextProperty",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
		return (NULL);
	    }
    bSKI = malloc(dwSize);
    if (!CertGetCertificateContextProperty(cert, CERT_KEY_IDENTIFIER_PROP_ID, bSKI, &dwSize)) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "CertGetCertificateContextProperty",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		free(bSKI);
		return (NULL);
	    }

    if (NULL == bSKI) {
	return(NULL);
    }

    res = xmlSecBase64Encode(bSKI, dwSize, 0);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBase64Encode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	free(bSKI);
	return(NULL);
    }
    free(bSKI);
    
    return(res);
}


static void 
xmlSecMSCryptoX509CertDebugDump(PCCERT_CONTEXT cert, FILE* output) {
    PCRYPT_INTEGER_BLOB sn;
    unsigned int i;
    LPSTR subject, issuer;
    DWORD dwSize;

    xmlSecAssert(cert != NULL);
    xmlSecAssert(output != NULL);

    dwSize = CertGetNameString(cert, CERT_NAME_RDN_TYPE, 0, NULL, NULL, 0);
    subject = (LPSTR)malloc(dwSize);
    dwSize = CertGetNameString(cert, CERT_NAME_RDN_TYPE, 0, NULL, subject, dwSize);
    dwSize = CertGetNameString(cert, CERT_NAME_RDN_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0);
    issuer = (LPSTR)malloc(dwSize);
    dwSize = CertGetNameString(cert, CERT_NAME_RDN_TYPE, CERT_NAME_ISSUER_FLAG, NULL, issuer, dwSize);

    fprintf(output, "=== X509 Certificate\n");
    fprintf(output, "==== Subject Name: %s\n", subject);
    fprintf(output, "==== Issuer Name: %s\n", issuer);
    if (subject) free(subject);
    if (issuer) free(issuer);
    sn = &(cert->pCertInfo->SerialNumber);

    for (i = 0; i < sn->cbData; i++) {
	if (i != sn->cbData - 1) {
	    fprintf(output, "%02x:", sn->pbData[i]);
	} else {
	    fprintf(output, "%02x", sn->pbData[i]);
	}
    }
    fprintf(output, "\n");
}


static void 
xmlSecMSCryptoX509CertDebugXmlDump(PCCERT_CONTEXT cert, FILE* output) {
    PCRYPT_INTEGER_BLOB sn;
    unsigned int i;
    LPSTR subject, issuer;
    DWORD dwSize;

    xmlSecAssert(cert != NULL);
    xmlSecAssert(output != NULL);

    dwSize = CertGetNameString(cert, CERT_NAME_RDN_TYPE, 0, NULL, NULL, 0);
    subject = (LPSTR)malloc(dwSize);
    dwSize = CertGetNameString(cert, CERT_NAME_RDN_TYPE, 0, NULL, subject, dwSize);
    dwSize = CertGetNameString(cert, CERT_NAME_RDN_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0);
    issuer = (LPSTR)malloc(dwSize);
    dwSize = CertGetNameString(cert, CERT_NAME_RDN_TYPE, CERT_NAME_ISSUER_FLAG, NULL, issuer, dwSize);

    fprintf(output, "=== X509 Certificate\n");
    fprintf(output, "==== Subject Name: %s\n", subject);
    fprintf(output, "==== Issuer Name: %s\n", issuer);
    if (subject) free(subject);
    if (issuer) free(issuer);
    sn = &(cert->pCertInfo->SerialNumber);

    for (i = 0; i < sn->cbData; i++) {
	if (i != sn->cbData - 1) {
	    fprintf(output, "%02x:", sn->pbData[i]);
	} else {
	    fprintf(output, "%02x", sn->pbData[i]);
	}
    }
    fprintf(output, "\n");
}


/**************************************************************************
 *
 * Raw X509 Certificate processing
 *
 *
 *************************************************************************/
static int		xmlSecMSCryptoKeyDataRawX509CertBinRead	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 const xmlSecByte* buf,
								 xmlSecSize bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyDataKlass xmlSecMSCryptoKeyDataRawX509CertKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),

    /* data */
    xmlSecNameRawX509Cert,
    xmlSecKeyDataUsageRetrievalMethodNodeBin, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefRawX509Cert,			/* const xmlChar* href; */
    NULL,					/* const xmlChar* dataNodeName; */
    xmlSecDSigNs,				/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    NULL,					/* xmlSecKeyDataInitializeMethod initialize; */
    NULL,					/* xmlSecKeyDataDuplicateMethod duplicate; */
    NULL,					/* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,					/* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    NULL,			 		/* xmlSecKeyDataGetTypeMethod getType; */
    NULL,					/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    NULL,					/* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,					/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecMSCryptoKeyDataRawX509CertBinRead,	/* xmlSecKeyDataBinReadMethod binRead; */
    NULL,					/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    NULL,					/* xmlSecKeyDataDebugDumpMethod debugDump; */
    NULL,					/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecMSCryptoKeyDataRawX509CertGetKlass:
 * 
 * The raw X509 certificates key data klass.
 *
 * Returns raw X509 certificates key data klass.
 */
xmlSecKeyDataId 
xmlSecMSCryptoKeyDataRawX509CertGetKlass(void) {
    return(&xmlSecMSCryptoKeyDataRawX509CertKlass);
}

static int
xmlSecMSCryptoKeyDataRawX509CertBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    const xmlSecByte* buf, xmlSecSize bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    PCCERT_CONTEXT cert;
    int ret;
    
    xmlSecAssert2(id == xmlSecMSCryptoKeyDataRawX509CertId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    cert = xmlSecMSCryptoX509CertDerRead(buf, bufSize);
    if(cert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoX509CertDerRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    data = xmlSecKeyEnsureData(key, xmlSecMSCryptoKeyDataX509Id);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecKeyEnsureData",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	CertFreeCertificateContext(cert);
	return(-1);
    }

    ret = xmlSecMSCryptoKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecMSCryptoKeyDataX509AdoptCert",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	CertFreeCertificateContext(cert);
	return(-1);
    }

    ret = xmlSecMSCryptoKeyDataX509VerifyAndExtractKey(data, key, keyInfoCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecMSCryptoKeyDataX509VerifyAndExtractKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

#endif /* XMLSEC_NO_X509 */
