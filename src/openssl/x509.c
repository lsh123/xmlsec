/** 
 * XMLSec library
 *
 * X509 support
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

#include <libxml/tree.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/openssl/x509.h>

/*************************************************************************
 *
 * X509 utility functions
 *
 ************************************************************************/
static int		xmlSecOpenSSLX509DataNodeRead		(xmlSecKeyDataPtr data,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLX509CertificateNodeRead	(xmlSecKeyDataPtr data,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLX509SubjectNameNodeRead	(xmlSecKeyDataPtr data,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLX509IssuerSerialNodeRead	(xmlSecKeyDataPtr data,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLX509SKINodeRead		(xmlSecKeyDataPtr data,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLX509CRLNodeRead		(xmlSecKeyDataPtr data,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataX509VerifyAndExtractKey(xmlSecKeyDataPtr data, 
								xmlSecKeyPtr key,
								xmlSecKeyInfoCtxPtr keyInfoCtx);
static xmlSecKeyDataPtr	xmlSecOpenSSLX509CertGetKey		(X509* cert);
static X509*		xmlSecOpenSSLX509CertDerRead		(const xmlSecByte* buf, 
								 xmlSecSize size);
static X509*		xmlSecOpenSSLX509CertBase64DerRead	(xmlChar* buf);
static xmlChar*		xmlSecOpenSSLX509CertBase64DerWrite	(X509* cert, 
								 int base64LineWrap);
static X509_CRL*	xmlSecOpenSSLX509CrlDerRead		(xmlSecByte* buf, 
								 xmlSecSize size);
static X509_CRL*	xmlSecOpenSSLX509CrlBase64DerRead	(xmlChar* buf);
static xmlChar*		xmlSecOpenSSLX509CrlBase64DerWrite	(X509_CRL* crl, 
								 int base64LineWrap);
static void		xmlSecOpenSSLX509CertDebugDump		(X509* cert, 
								 FILE* output);
static void		xmlSecOpenSSLX509CertDebugXmlDump	(X509* cert, 
								 FILE* output);
static int		xmlSecOpenSSLX509CertGetTime		(ASN1_TIME* t,
								 time_t* res);

/*************************************************************************
 *
 * Internal OpenSSL X509 data CTX
 *
 ************************************************************************/
typedef struct _xmlSecOpenSSLX509DataCtx		xmlSecOpenSSLX509DataCtx,
							*xmlSecOpenSSLX509DataCtxPtr;
struct _xmlSecOpenSSLX509DataCtx {
    X509*		keyCert;
    STACK_OF(X509)*	certsList;
    STACK_OF(X509_CRL)*	crlsList;
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
 * xmlSecOpenSSLX509DataCtx is located after xmlSecTransform
 *
 *************************************************************************/
#define xmlSecOpenSSLX509DataSize	\
    (sizeof(xmlSecKeyData) + sizeof(xmlSecOpenSSLX509DataCtx))	
#define xmlSecOpenSSLX509DataGetCtx(data) \
    ((xmlSecOpenSSLX509DataCtxPtr)(((xmlSecByte*)(data)) + sizeof(xmlSecKeyData)))

static int		xmlSecOpenSSLKeyDataX509Initialize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataX509Duplicate	(xmlSecKeyDataPtr dst,
								 xmlSecKeyDataPtr src);
static void		xmlSecOpenSSLKeyDataX509Finalize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataX509XmlRead		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataX509XmlWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static xmlSecKeyDataType xmlSecOpenSSLKeyDataX509GetType	(xmlSecKeyDataPtr data);
static const xmlChar*	xmlSecOpenSSLKeyDataX509GetIdentifier	(xmlSecKeyDataPtr data);

static void		xmlSecOpenSSLKeyDataX509DebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecOpenSSLKeyDataX509DebugXmlDump	(xmlSecKeyDataPtr data,
								 FILE* output);



static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataX509Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecOpenSSLX509DataSize,

    /* data */
    xmlSecNameX509Data,
    xmlSecKeyDataUsageKeyInfoNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefX509Data,				/* const xmlChar* href; */
    xmlSecNodeX509Data,				/* const xmlChar* dataNodeName; */
    xmlSecDSigNs,				/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecOpenSSLKeyDataX509Initialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataX509Duplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataX509Finalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,					/* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecOpenSSLKeyDataX509GetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    NULL,					/* xmlSecKeyDataGetSizeMethod getSize; */
    xmlSecOpenSSLKeyDataX509GetIdentifier,	/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    xmlSecOpenSSLKeyDataX509XmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataX509XmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,					/* xmlSecKeyDataBinReadMethod binRead; */
    NULL,					/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataX509DebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataX509DebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecOpenSSLKeyDataX509GetKlass:
 * 
 * The OpenSSL X509 key data klass (http://www.w3.org/TR/xmldsig-core/#sec-X509Data).
 *
 * Returns the X509 data klass.
 */
xmlSecKeyDataId 
xmlSecOpenSSLKeyDataX509GetKlass(void) {
    return(&xmlSecOpenSSLKeyDataX509Klass);
}

/**
 * xmlSecOpenSSLKeyDataX509GetKeyCert:
 * @data:		the pointer to X509 key data.
 *
 * Gets the certificate from which the key was extracted. 
 *
 * Returns the key's certificate or NULL if key data was not used for key
 * extraction or an error occurs.
 */
X509* 	
xmlSecOpenSSLKeyDataX509GetKeyCert(xmlSecKeyDataPtr data) {
    xmlSecOpenSSLX509DataCtxPtr ctx;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), NULL);

    ctx = xmlSecOpenSSLX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->keyCert);
}

/**
 * xmlSecOpenSSLKeyDataX509AdoptKeyCert:
 * @data:		the pointer to X509 key data.
 * @cert:		the pointer to OpenSSL X509 certificate.
 *
 * Sets the key's certificate in @data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLKeyDataX509AdoptKeyCert(xmlSecKeyDataPtr data, X509* cert) {
    xmlSecOpenSSLX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecOpenSSLX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    
    if(ctx->keyCert != NULL) {
	X509_free(ctx->keyCert);
    }
    ctx->keyCert = cert;
    return(0);
}

/**
 * xmlSecOpenSSLKeyDataX509AdoptCert:
 * @data:		the pointer to X509 key data.
 * @cert:		the pointer to OpenSSL X509 certificate.
 *
 * Adds certificate to the X509 key data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecOpenSSLKeyDataX509AdoptCert(xmlSecKeyDataPtr data, X509* cert) {
    xmlSecOpenSSLX509DataCtxPtr ctx;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecOpenSSLX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    
    if(ctx->certsList == NULL) {
	ctx->certsList = sk_X509_new_null();
	if(ctx->certsList == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			"sk_X509_new_null",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);	
	}
    }
    
    ret = sk_X509_push(ctx->certsList, cert);
    if(ret < 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "sk_X509_push",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }
        
    return(0);
}

/**
 * xmlSecOpenSSLKeyDataX509GetCert:
 * @data:		the pointer to X509 key data.
 * @pos:		the desired certificate position.
 * 
 * Gets a certificate from X509 key data.
 *
 * Returns the pointer to certificate or NULL if @pos is larger than the 
 * number of certificates in @data or an error occurs.
 */
X509* 
xmlSecOpenSSLKeyDataX509GetCert(xmlSecKeyDataPtr data, xmlSecSize pos) {
    xmlSecOpenSSLX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), NULL);

    ctx = xmlSecOpenSSLX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->certsList != NULL, NULL);
    xmlSecAssert2((int)pos < sk_X509_num(ctx->certsList), NULL);

    return(sk_X509_value(ctx->certsList, pos));
}

/**
 * xmlSecOpenSSLKeyDataX509GetCertsSize:
 * @data:		the pointer to X509 key data.
 *
 * Gets the number of certificates in @data.
 *
 * Returns te number of certificates in @data.
 */
xmlSecSize 	
xmlSecOpenSSLKeyDataX509GetCertsSize(xmlSecKeyDataPtr data) {
    xmlSecOpenSSLX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), 0);

    ctx = xmlSecOpenSSLX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return((ctx->certsList != NULL) ? sk_X509_num(ctx->certsList) : 0);
}

/**
 * xmlSecOpenSSLKeyDataX509AdoptCrl:
 * @data:		the pointer to X509 key data.
 * @crl:		the pointer to OpenSSL X509 CRL.
 *
 * Adds CRL to the X509 key data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecOpenSSLKeyDataX509AdoptCrl(xmlSecKeyDataPtr data, X509_CRL* crl) {
    xmlSecOpenSSLX509DataCtxPtr ctx;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(crl != NULL, -1);

    ctx = xmlSecOpenSSLX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    
    if(ctx->crlsList == NULL) {
	ctx->crlsList = sk_X509_CRL_new_null();
	if(ctx->crlsList == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			"sk_X509_CRL_new_null",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);	
	}
    }
    
    ret = sk_X509_CRL_push(ctx->crlsList, crl);
    if(ret < 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "sk_X509_CRL_push",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }
        
    return(0);
}

/**
 * xmlSecOpenSSLKeyDataX509GetCrl:
 * @data:		the pointer to X509 key data.
 * @pos:		the desired CRL position.
 * 
 * Gets a CRL from X509 key data.
 *
 * Returns the pointer to CRL or NULL if @pos is larger than the 
 * number of CRLs in @data or an error occurs.
 */
X509_CRL* 
xmlSecOpenSSLKeyDataX509GetCrl(xmlSecKeyDataPtr data, xmlSecSize pos) {
    xmlSecOpenSSLX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), NULL);

    ctx = xmlSecOpenSSLX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    xmlSecAssert2(ctx->crlsList != NULL, NULL);
    xmlSecAssert2((int)pos < sk_X509_CRL_num(ctx->crlsList), NULL);

    return(sk_X509_CRL_value(ctx->crlsList, pos));
}

/**
 * xmlSecOpenSSLKeyDataX509GetCrlsSize:
 * @data:		the pointer to X509 key data.
 *
 * Gets the number of CRLs in @data.
 *
 * Returns te number of CRLs in @data.
 */
xmlSecSize 
xmlSecOpenSSLKeyDataX509GetCrlsSize(xmlSecKeyDataPtr data) {
    xmlSecOpenSSLX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), 0);

    ctx = xmlSecOpenSSLX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return((ctx->crlsList != NULL) ? sk_X509_CRL_num(ctx->crlsList) : 0);
}

static int	
xmlSecOpenSSLKeyDataX509Initialize(xmlSecKeyDataPtr data) {
    xmlSecOpenSSLX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);

    ctx = xmlSecOpenSSLX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLX509DataCtx));
    return(0);
}

static int
xmlSecOpenSSLKeyDataX509Duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    X509* certSrc;
    X509* certDst;
    X509_CRL* crlSrc;
    X509_CRL* crlDst;
    xmlSecSize size, pos;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataX509Id), -1);
    
    /* copy certsList */
    size = xmlSecOpenSSLKeyDataX509GetCertsSize(src);
    for(pos = 0; pos < size; ++pos) {
	certSrc = xmlSecOpenSSLKeyDataX509GetCert(src, pos);
	if(certSrc == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(src)),
			"xmlSecOpenSSLKeyDataX509GetCert",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"pos=%d", pos);
	    return(-1);
	}
	
	certDst = X509_dup(certSrc);
	if(certDst == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"X509_dup",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	
	ret = xmlSecOpenSSLKeyDataX509AdoptCert(dst, certDst);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"xmlSecOpenSSLKeyDataX509AdoptCert",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    X509_free(certDst);
	    return(-1);
	}
    }

    /* copy crls */
    size = xmlSecOpenSSLKeyDataX509GetCrlsSize(src);
    for(pos = 0; pos < size; ++pos) {
	crlSrc = xmlSecOpenSSLKeyDataX509GetCrl(src, pos);
	if(crlSrc == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(src)),
			"xmlSecOpenSSLKeyDataX509GetCrl",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"pos=%d", pos);
	    return(-1);
	}
	
	crlDst = X509_CRL_dup(crlSrc);
	if(crlDst == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"X509_CRL_dup",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	
	ret = xmlSecOpenSSLKeyDataX509AdoptCrl(dst, crlDst);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"xmlSecOpenSSLKeyDataX509AdoptCrl",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    X509_CRL_free(crlDst);
	    return(-1);
	}
    }

    /* copy key cert if exist */
    certSrc = xmlSecOpenSSLKeyDataX509GetKeyCert(src);
    if(certSrc != NULL) {
	certDst = X509_dup(certSrc);
	if(certDst == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"X509_dup",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	ret = xmlSecOpenSSLKeyDataX509AdoptKeyCert(dst, certDst);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"xmlSecOpenSSLKeyDataX509AdoptKeyCert",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    X509_free(certDst);
	    return(-1);
	}
    }
    return(0);
}

static void
xmlSecOpenSSLKeyDataX509Finalize(xmlSecKeyDataPtr data) {
    xmlSecOpenSSLX509DataCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id));

    ctx = xmlSecOpenSSLX509DataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    if(ctx->certsList != NULL) {
	sk_X509_pop_free(ctx->certsList, X509_free); 	
    }
    if(ctx->crlsList != NULL) {
	sk_X509_CRL_pop_free(ctx->crlsList, X509_CRL_free); 	
    }
    if(ctx->keyCert != NULL) {
	X509_free(ctx->keyCert);
    }
    memset(ctx, 0, sizeof(xmlSecOpenSSLX509DataCtx));
}

static int
xmlSecOpenSSLKeyDataX509XmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    int ret;
    
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataX509Id, -1);
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
    
    ret = xmlSecOpenSSLX509DataNodeRead(data, node, keyInfoCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLX509DataNodeRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS) == 0) {
        ret = xmlSecOpenSSLKeyDataX509VerifyAndExtractKey(data, key, keyInfoCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecOpenSSLKeyDataX509VerifyAndExtractKey",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
        }
    }
    return(0);
}

static int 
xmlSecOpenSSLKeyDataX509XmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    xmlNodePtr cur;
    xmlChar* buf;
    X509* cert;
    X509_CRL* crl;
    xmlSecSize size, pos;
    				
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* todo: flag in ctx remove all existing content */
    if(0) {
        xmlNodeSetContent(node, NULL);
    }

    data = xmlSecKeyGetData(key, id);
    if(data == NULL) {
	/* no x509 data in the key */
	return(0);	
    }

    /* write certs */
    size = xmlSecOpenSSLKeyDataX509GetCertsSize(data);
    for(pos = 0; pos < size; ++pos) {
	cert = xmlSecOpenSSLKeyDataX509GetCert(data, pos);
	if(cert == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecOpenSSLKeyDataX509GetCert",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"pos=%d", pos);
	    return(-1);
	}
	
	/* set base64 lines size from context */
	buf = xmlSecOpenSSLX509CertBase64DerWrite(cert, keyInfoCtx->base64LineSize); 
	if(buf == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecOpenSSLX509CertBase64DerWrite",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	
	cur = xmlSecAddChild(node, xmlSecNodeX509Certificate, xmlSecDSigNs);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
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
    }    

    /* write crls */
    size = xmlSecOpenSSLKeyDataX509GetCrlsSize(data);
    for(pos = 0; pos < size; ++pos) {
	crl = xmlSecOpenSSLKeyDataX509GetCrl(data, pos);
	if(crl == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecOpenSSLKeyDataX509GetCrl",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"pos=%d", pos);
	    return(-1);
	}
	
	/* set base64 lines size from context */
	buf = xmlSecOpenSSLX509CrlBase64DerWrite(crl, keyInfoCtx->base64LineSize); 
	if(buf == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecOpenSSLX509CrlBase64DerWrite",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	
	cur = xmlSecAddChild(node, xmlSecNodeX509CRL, xmlSecDSigNs);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
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
    }    
    
    return(0);
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataX509GetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), xmlSecKeyDataTypeUnknown);

    /* TODO: return verified/not verified status */    
    return(xmlSecKeyDataTypeUnknown);
}

static const xmlChar*
xmlSecOpenSSLKeyDataX509GetIdentifier(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), NULL);
    
    /* TODO */    
    return(NULL);
}

static void 
xmlSecOpenSSLKeyDataX509DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    X509* cert;
    xmlSecSize size, pos;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== X509 Data:\n");
    cert = xmlSecOpenSSLKeyDataX509GetKeyCert(data);
    if(cert != NULL) {
	fprintf(output, "==== Key Certificate:\n");
	xmlSecOpenSSLX509CertDebugDump(cert, output);
    }
    
    size = xmlSecOpenSSLKeyDataX509GetCertsSize(data);
    for(pos = 0; pos < size; ++pos) {
	cert = xmlSecOpenSSLKeyDataX509GetCert(data, pos);
	if(cert == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			"xmlSecOpenSSLKeyDataX509GetCert",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"pos=%d", pos);
	    return;
	}
	fprintf(output, "==== Certificate:\n");
	xmlSecOpenSSLX509CertDebugDump(cert, output);
    }
    
    /* we don't print out crls */
}

static void
xmlSecOpenSSLKeyDataX509DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    X509* cert;
    xmlSecSize size, pos;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<X509Data>\n");
    cert = xmlSecOpenSSLKeyDataX509GetKeyCert(data);
    if(cert != NULL) {
	fprintf(output, "<KeyCertificate>\n");
	xmlSecOpenSSLX509CertDebugXmlDump(cert, output);
	fprintf(output, "</KeyCertificate>\n");
    }
    
    size = xmlSecOpenSSLKeyDataX509GetCertsSize(data);
    for(pos = 0; pos < size; ++pos) {
	cert = xmlSecOpenSSLKeyDataX509GetCert(data, pos);
	if(cert == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			"xmlSecOpenSSLKeyDataX509GetCert",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"pos=%d", pos);
	    return;
	}
	fprintf(output, "<Certificate>\n");
	xmlSecOpenSSLX509CertDebugXmlDump(cert, output);
	fprintf(output, "</Certificate>\n");
    }
    
    /* we don't print out crls */
    fprintf(output, "</X509Data>\n");
}

static int
xmlSecOpenSSLX509DataNodeRead(xmlSecKeyDataPtr data, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlNodePtr cur; 
    int ret;
        
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    
    for(cur = xmlSecGetNextElementNode(node->children);
	cur != NULL;
	cur = xmlSecGetNextElementNode(cur->next)) {
	
	ret = 0;
	if(xmlSecCheckNodeName(cur, xmlSecNodeX509Certificate, xmlSecDSigNs)) {
	    ret = xmlSecOpenSSLX509CertificateNodeRead(data, cur, keyInfoCtx);
	} else if(xmlSecCheckNodeName(cur, xmlSecNodeX509SubjectName, xmlSecDSigNs)) {
	    ret = xmlSecOpenSSLX509SubjectNameNodeRead(data, cur, keyInfoCtx);
	} else if(xmlSecCheckNodeName(cur, xmlSecNodeX509IssuerSerial, xmlSecDSigNs)) {
	    ret = xmlSecOpenSSLX509IssuerSerialNodeRead(data, cur, keyInfoCtx);
	} else if(xmlSecCheckNodeName(cur, xmlSecNodeX509SKI, xmlSecDSigNs)) {
	    ret = xmlSecOpenSSLX509SKINodeRead(data, cur, keyInfoCtx);
	} else if(xmlSecCheckNodeName(cur, xmlSecNodeX509CRL, xmlSecDSigNs)) {
	    ret = xmlSecOpenSSLX509CRLNodeRead(data, cur, keyInfoCtx);
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
xmlSecOpenSSLX509CertificateNodeRead(xmlSecKeyDataPtr data, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {	
    xmlChar *content;
    X509* cert;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    content = xmlNodeGetContent(node);
    if(content == NULL){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(node)),
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    cert = xmlSecOpenSSLX509CertBase64DerRead(content);
    if(cert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecOpenSSLX509CertBase64DerRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFree(content);
	return(-1);
    }    
    
    ret = xmlSecOpenSSLKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecOpenSSLKeyDataX509AdoptCert",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	X509_free(cert);
	xmlFree(content);
	return(-1);
    }
     
    xmlFree(content);
    return(0);
}

static int		
xmlSecOpenSSLX509SubjectNameNodeRead(xmlSecKeyDataPtr data, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {	
    xmlSecKeyDataStorePtr x509Store;
    xmlChar* subject;
    X509* cert;
    X509* cert2;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecOpenSSLX509StoreId);
    if(x509Store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecKeysMngrGetDataStore",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    subject = xmlNodeGetContent(node);
    if(subject == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(node)),
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    cert = xmlSecOpenSSLX509StoreFindCert(x509Store, subject, NULL, NULL, NULL, keyInfoCtx);
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

    cert2 = X509_dup(cert);
    if(cert2 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "X509_dup",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFree(subject);
	return(-1);
    }
    
    ret = xmlSecOpenSSLKeyDataX509AdoptCert(data, cert2);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecOpenSSLKeyDataX509AdoptCert",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	X509_free(cert2);
	xmlFree(subject);
	return(-1);
    }
    
    xmlFree(subject);
    return(0);
}

static int 
xmlSecOpenSSLX509IssuerSerialNodeRead(xmlSecKeyDataPtr data, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataStorePtr x509Store;
    xmlNodePtr cur;
    xmlChar *issuerName;
    xmlChar *issuerSerial;    
    X509* cert;
    X509* cert2;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecOpenSSLX509StoreId);
    if(x509Store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecKeysMngrGetDataStore",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    cur = xmlSecGetNextElementNode(node->children);

    /* the first is required node X509IssuerName */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, xmlSecNodeX509IssuerName, xmlSecDSigNs)) {
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

    cert = xmlSecOpenSSLX509StoreFindCert(x509Store, NULL, issuerName, issuerSerial, NULL, keyInfoCtx);
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

    cert2 = X509_dup(cert);
    if(cert2 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "X509_dup",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFree(issuerSerial);
	xmlFree(issuerName);
	return(-1);
    }

    ret = xmlSecOpenSSLKeyDataX509AdoptCert(data, cert2);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecOpenSSLKeyDataX509AdoptCert",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	X509_free(cert2);
	xmlFree(issuerSerial);
	xmlFree(issuerName);
	return(-1);
    }
    
    xmlFree(issuerSerial);
    xmlFree(issuerName);
    return(0);
}

static int 
xmlSecOpenSSLX509SKINodeRead(xmlSecKeyDataPtr data, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataStorePtr x509Store;
    xmlChar* ski;
    X509* cert;
    X509* cert2;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecOpenSSLX509StoreId);
    if(x509Store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecKeysMngrGetDataStore",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    ski = xmlNodeGetContent(node);
    if(ski == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(node)),
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeX509SKI));
	return(-1);
    }

    cert = xmlSecOpenSSLX509StoreFindCert(x509Store, NULL, NULL, NULL, ski, keyInfoCtx);
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

    cert2 = X509_dup(cert);
    if(cert2 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "X509_dup",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFree(ski);
	return(-1);
    }

    ret = xmlSecOpenSSLKeyDataX509AdoptCert(data, cert2);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecOpenSSLKeyDataX509AdoptCert",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	X509_free(cert2);
	xmlFree(ski);
	return(-1);
    }
    
    xmlFree(ski);
    return(0);
}

static int 
xmlSecOpenSSLX509CRLNodeRead(xmlSecKeyDataPtr data, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlChar *content;
    X509_CRL* crl;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    content = xmlNodeGetContent(node);
    if(content == NULL){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(node)),
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    crl = xmlSecOpenSSLX509CrlBase64DerRead(content);
    if(crl == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecOpenSSLX509CrlBase64DerRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFree(content);
	return(-1);
    }    
    
    ret = xmlSecOpenSSLKeyDataX509AdoptCrl(data, crl);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecOpenSSLKeyDataX509AdoptCrl",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	X509_CRL_free(crl);
	xmlFree(content);
	return(-1);
    }
     
    xmlFree(content);
    return(0);
}

static int
xmlSecOpenSSLKeyDataX509VerifyAndExtractKey(xmlSecKeyDataPtr data, xmlSecKeyPtr key,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecOpenSSLX509DataCtxPtr ctx;
    xmlSecKeyDataStorePtr x509Store;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    ctx = xmlSecOpenSSLX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecOpenSSLX509StoreId);
    if(x509Store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecKeysMngrGetDataStore",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    if((ctx->keyCert == NULL) && (ctx->certsList != NULL) && (xmlSecKeyGetValue(key) == NULL)) {
	X509* cert;
	
	cert = xmlSecOpenSSLX509StoreVerify(x509Store, ctx->certsList, ctx->crlsList, keyInfoCtx);
	if(cert != NULL) {
	    xmlSecKeyDataPtr keyValue;
	    
	    ctx->keyCert = X509_dup(cert);
	    if(ctx->keyCert == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			    "X509_dup",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	
	    keyValue = xmlSecOpenSSLX509CertGetKey(ctx->keyCert);
	    if(keyValue == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			    "xmlSecOpenSSLX509CertGetKey",
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
	    
	    if((X509_get_notBefore(ctx->keyCert) != NULL) && (X509_get_notAfter(ctx->keyCert) != NULL)) {
		ret = xmlSecOpenSSLX509CertGetTime(X509_get_notBefore(ctx->keyCert), &(key->notValidBefore));
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
			        xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
				"xmlSecOpenSSLX509CertGetTime",
			        XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"notValidBefore");
		    return(-1);
		}
		ret = xmlSecOpenSSLX509CertGetTime(X509_get_notAfter(ctx->keyCert), &(key->notValidAfter));
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
			        xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
				"xmlSecOpenSSLX509CertGetTime",
			        XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"notValidAfter");
		    return(-1);
		}
	    } else {
		key->notValidBefore = key->notValidAfter = 0;
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

#ifdef HAVE_TIMEGM
extern time_t timegm (struct tm *tm);
#else  /* HAVE_TIMEGM */
#ifdef WIN32
#define timegm(tm)	(mktime(tm) - _timezone)
#else /* WIN32 */
/* Absolutely not the best way but it's the only ANSI compatible way I know.
 * If you system has a native struct tm --> GMT time_t conversion function
 * (like timegm) use it instead.
 */
static time_t 
my_timegm(struct tm *t) {  
    time_t tl, tb;  
    struct tm *tg;  

    tl = mktime (t);  
    if(tl == -1) {
	t->tm_hour--;
	tl = mktime (t);
	if (tl == -1) {
	    return -1;
	}
	tl += 3600;    
    }  
    tg = gmtime (&tl);  
    tg->tm_isdst = 0;  
    tb = mktime (tg);  
    if (tb == -1) {
	tg->tm_hour--;
	tb = mktime (tg);
	if (tb == -1) {
	    return -1;
	}
	tb += 3600;    
    }  
    return (tl - (tb - tl)); 
}

#define timegm(tm) my_timegm(tm)
#endif /* WIN32 */
#endif /* HAVE_TIMEGM */

static int
xmlSecOpenSSLX509CertGetTime(ASN1_TIME* t, time_t* res) {
    struct tm tm;
    int offset;
    
    xmlSecAssert2(t != NULL, -1);
    xmlSecAssert2(res != NULL, -1);

    (*res) = 0;
#ifndef XMLSEC_OPENSSL_096
    if(!ASN1_TIME_check(t)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "ASN1_TIME_check",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_OPENSSL_096 */
        
    memset(&tm, 0, sizeof(tm));

#define g2(p) (((p)[0]-'0')*10+(p)[1]-'0')
    if(t->type == V_ASN1_UTCTIME) {
	xmlSecAssert2(t->length > 12, -1);

	
	/* this code is copied from OpenSSL asn1/a_utctm.c file */	
	tm.tm_year = g2(t->data);
	if(tm.tm_year < 50) {
	    tm.tm_year += 100;
	}
	tm.tm_mon  = g2(t->data + 2) - 1;
	tm.tm_mday = g2(t->data + 4);
	tm.tm_hour = g2(t->data + 6);
	tm.tm_min  = g2(t->data + 8);
	tm.tm_sec  = g2(t->data + 10);
	if(t->data[12] == 'Z') {
	    offset = 0;
	} else {
	    xmlSecAssert2(t->length > 16, -1);
	    
	    offset = g2(t->data + 13) * 60 + g2(t->data + 15);
	    if(t->data[12] == '-') {
		offset = -offset;
	    }
	}
	tm.tm_isdst = -1;
    } else {
	xmlSecAssert2(t->length > 14, -1);
	
	tm.tm_year = g2(t->data) * 100 + g2(t->data + 2);
	tm.tm_mon  = g2(t->data + 4) - 1;
	tm.tm_mday = g2(t->data + 6);
	tm.tm_hour = g2(t->data + 8);
	tm.tm_min  = g2(t->data + 10);
	tm.tm_sec  = g2(t->data + 12);
	if(t->data[14] == 'Z') {
	    offset = 0;
	} else {
	    xmlSecAssert2(t->length > 18, -1);
	    
	    offset = g2(t->data + 15) * 60 + g2(t->data + 17);
	    if(t->data[14] == '-') {
		offset = -offset;
	    }
	}
	tm.tm_isdst = -1;
    }
#undef g2
    (*res) = timegm(&tm) - offset * 60;
    return(0);
}

static xmlSecKeyDataPtr	
xmlSecOpenSSLX509CertGetKey(X509* cert) {
    xmlSecKeyDataPtr data;
    EVP_PKEY *pKey = NULL;
    
    xmlSecAssert2(cert != NULL, NULL);

    pKey = X509_get_pubkey(cert);
    if(pKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "X509_get_pubkey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }    

    data = xmlSecOpenSSLEvpKeyAdopt(pKey);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecOpenSSLEvpKeyAdopt",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	EVP_PKEY_free(pKey);
	return(NULL);	    
    }    
    
    return(data);
}

static X509*
xmlSecOpenSSLX509CertBase64DerRead(xmlChar* buf) {
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
    
    return(xmlSecOpenSSLX509CertDerRead((xmlSecByte*)buf, ret));
}

static X509*
xmlSecOpenSSLX509CertDerRead(const xmlSecByte* buf, xmlSecSize size) {
    X509 *cert = NULL;
    BIO *mem = NULL;
    int ret;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);
    
    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "BIO_new",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_s_mem");
	return(NULL);
    }
    
    ret = BIO_write(mem, buf, size);
    if(ret <= 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "BIO_write",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "size=%d", size);
	BIO_free_all(mem);
	return(NULL);
    }

    cert = d2i_X509_bio(mem, NULL);
    if(cert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "d2i_X509_bio",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	BIO_free_all(mem);
	return(NULL);
    }

    BIO_free_all(mem);
    return(cert);
}

static xmlChar*
xmlSecOpenSSLX509CertBase64DerWrite(X509* cert, int base64LineWrap) {
    xmlChar *res = NULL;
    BIO *mem = NULL;
    xmlSecByte *p = NULL;
    long size;

    xmlSecAssert2(cert != NULL, NULL);
	
    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "BIO_new",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_s_mem");
	return(NULL);
    }

    /* todo: add error checks */
    i2d_X509_bio(mem, cert);
    BIO_flush(mem);
        
    size = BIO_get_mem_data(mem, &p);
    if((size <= 0) || (p == NULL)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "BIO_get_mem_data",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	BIO_free_all(mem);
	return(NULL);
    }
    
    res = xmlSecBase64Encode(p, size, base64LineWrap);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBase64Encode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	BIO_free_all(mem);
	return(NULL);
    }    

    BIO_free_all(mem);
    return(res);
}

static X509_CRL*
xmlSecOpenSSLX509CrlBase64DerRead(xmlChar* buf) {
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
    
    return(xmlSecOpenSSLX509CrlDerRead((xmlSecByte*)buf, ret));
}

static X509_CRL*
xmlSecOpenSSLX509CrlDerRead(xmlSecByte* buf, xmlSecSize size) {
    X509_CRL *crl = NULL;
    BIO *mem = NULL;
    int ret;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);
    
    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "BIO_new",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_s_mem");
	return(NULL);
    }
    
    ret = BIO_write(mem, buf, size);
    if(ret <= 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "BIO_write",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "size=%d", size);
	BIO_free_all(mem);
	return(NULL);
    }

    crl = d2i_X509_CRL_bio(mem, NULL);
    if(crl == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "d2i_X509_CRL_bio",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	BIO_free_all(mem);
	return(NULL);
    }

    BIO_free_all(mem);
    return(crl);
}

static xmlChar*
xmlSecOpenSSLX509CrlBase64DerWrite(X509_CRL* crl, int base64LineWrap) {
    xmlChar *res = NULL;
    BIO *mem = NULL;
    xmlSecByte *p = NULL;
    long size;

    xmlSecAssert2(crl != NULL, NULL);
	
    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "BIO_new",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_s_mem");
	return(NULL);
    }

    /* todo: add error checks */
    i2d_X509_CRL_bio(mem, crl);
    BIO_flush(mem);
        
    size = BIO_get_mem_data(mem, &p);
    if((size <= 0) || (p == NULL)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "BIO_get_mem_data",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	BIO_free_all(mem);
	return(NULL);
    }
    
    res = xmlSecBase64Encode(p, size, base64LineWrap);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBase64Encode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	BIO_free_all(mem);
	return(NULL);
    }    

    BIO_free_all(mem);    
    return(res);
}

static void 
xmlSecOpenSSLX509CertDebugDump(X509* cert, FILE* output) {
    char buf[1024];
    BIGNUM *bn = NULL;

    xmlSecAssert(cert != NULL);
    xmlSecAssert(output != NULL);

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
xmlSecOpenSSLX509CertDebugXmlDump(X509* cert, FILE* output) {
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


/**************************************************************************
 *
 * Raw X509 Certificate processing
 *
 *
 *************************************************************************/
static int		xmlSecOpenSSLKeyDataRawX509CertBinRead	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 const xmlSecByte* buf,
								 xmlSecSize bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataRawX509CertKlass = {
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
    xmlSecOpenSSLKeyDataRawX509CertBinRead,	/* xmlSecKeyDataBinReadMethod binRead; */
    NULL,					/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    NULL,					/* xmlSecKeyDataDebugDumpMethod debugDump; */
    NULL,					/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecOpenSSLKeyDataRawX509CertGetKlass:
 * 
 * The raw X509 certificates key data klass.
 *
 * Returns raw X509 certificates key data klass.
 */
xmlSecKeyDataId 
xmlSecOpenSSLKeyDataRawX509CertGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataRawX509CertKlass);
}

static int
xmlSecOpenSSLKeyDataRawX509CertBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    const xmlSecByte* buf, xmlSecSize bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    X509* cert;
    int ret;
    
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataRawX509CertId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    cert = xmlSecOpenSSLX509CertDerRead(buf, bufSize);
    if(cert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecOpenSSLX509CertDerRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    data = xmlSecKeyEnsureData(key, xmlSecOpenSSLKeyDataX509Id);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecKeyEnsureData",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	X509_free(cert);
	return(-1);
    }
    
    ret = xmlSecOpenSSLKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLKeyDataX509AdoptCert",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	X509_free(cert);
	return(-1);
    }

    ret = xmlSecOpenSSLKeyDataX509VerifyAndExtractKey(data, key, keyInfoCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLKeyDataX509VerifyAndExtractKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

#endif /* XMLSEC_NO_X509 */
