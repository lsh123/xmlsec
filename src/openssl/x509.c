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
static X509*		xmlSecOpenSSLX509CertDerRead		(const unsigned char* buf, 
								 size_t size);
static X509*		xmlSecOpenSSLX509CertBase64DerRead	(xmlChar* buf);
static xmlChar*		xmlSecOpenSSLX509CertBase64DerWrite	(X509* cert, 
								 int base64LineWrap);
static X509_CRL*	xmlSecOpenSSLX509CrlDerRead		(unsigned char* buf, 
								 size_t size);
static X509_CRL*	xmlSecOpenSSLX509CrlBase64DerRead	(xmlChar* buf);
static xmlChar*		xmlSecOpenSSLX509CrlBase64DerWrite	(X509_CRL* crl, 
								 int base64LineWrap);
static void		xmlSecOpenSSLX509CertDebugDump		(X509* cert, 
								 FILE* output);
static void		xmlSecOpenSSLX509CertDebugXmlDump	(X509* cert, 
								 FILE* output);

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
 *************************************************************************/
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
    sizeof(xmlSecKeyData),

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
};

xmlSecKeyDataId 
xmlSecOpenSSLKeyDataX509GetKlass(void) {
    return(&xmlSecOpenSSLKeyDataX509Klass);
}

/**
 * xmlSecKeyData mapping for X509 data:
 * reserved0 --> all certs 		: STACK_OF(X509)*
 * reserved1 --> all crls  		: STACK_OF(X509_CRL)*
 * reserved2 --> verified cert		: X509*
 * reserved3 --> verified cert subject  : xmlChar*
 */
#define  xmlSecOpenSSLKeyDataX509GetAllCerts(data) \
	((( data ) != NULL) ? ((STACK_OF(X509)*) (( data )->reserved0) ) : NULL)
#define  xmlSecOpenSSLKeyDataX509GetAllCrls(data) \
	((( data ) != NULL) ? ((STACK_OF(X509_CRL)*) (( data )->reserved1) ) : NULL)
#define  xmlSecOpenSSLKeyDataX509GetVerifiedCert(data) \
	((( data ) != NULL) ? ((X509*) (( data )->reserved2) ) : NULL)
#define  xmlSecOpenSSLKeyDataX509GetVerifiedCertSubject(data) \
	((( data ) != NULL) ? ((xmlChar*) (( data )->reserved3) ) : NULL)

 
X509* 	
xmlSecOpenSSLKeyDataX509GetVerified(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), NULL);

    return(xmlSecOpenSSLKeyDataX509GetVerifiedCert(data));
}

int
xmlSecOpenSSLKeyDataX509AdoptVerified(xmlSecKeyDataPtr data, X509* cert) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);
    
    if(xmlSecOpenSSLKeyDataX509GetVerifiedCert(data) != NULL) {
	X509_free(xmlSecOpenSSLKeyDataX509GetVerifiedCert(data));
    }
    data->reserved2 = cert;
    return(0);
}

int 
xmlSecOpenSSLKeyDataX509AdoptCert(xmlSecKeyDataPtr data, X509* cert) {
    STACK_OF(X509)* certs;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);
    
    certs = xmlSecOpenSSLKeyDataX509GetAllCerts(data);
    if(certs == NULL) {
	certs = sk_X509_new_null();
	if(certs == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"sk_X509_new_null");
	    return(-1);	
	}
	data->reserved0 = certs;
    }
    
    ret = sk_X509_push(certs, cert);
    if(ret < 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "sk_X509_push");
	return(-1);	
    }
        
    return(0);
}

X509* 
xmlSecOpenSSLKeyDataX509GetCert(xmlSecKeyDataPtr data, size_t pos) {
    STACK_OF(X509)* certs;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), NULL);

    certs = xmlSecOpenSSLKeyDataX509GetAllCerts(data);
    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2((int)pos < sk_X509_num(certs), NULL);

    return(sk_X509_value(certs, pos));
}

size_t 	
xmlSecOpenSSLKeyDataX509GetCertsNumber(xmlSecKeyDataPtr data) {
    STACK_OF(X509)* certs;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), 0);

    certs = xmlSecOpenSSLKeyDataX509GetAllCerts(data);
    return((certs != NULL) ? sk_X509_num(certs) : 0);
}

int 
xmlSecOpenSSLKeyDataX509AdoptCrl(xmlSecKeyDataPtr data, X509_CRL* crl) {
    STACK_OF(X509_CRL)* crls;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(crl != NULL, -1);
    
    crls = xmlSecOpenSSLKeyDataX509GetAllCrls(data);
    if(crls == NULL) {
	crls = sk_X509_CRL_new_null();
	if(crls == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"sk_X509_CRL_new_null");
	    return(-1);	
	}
	data->reserved1 = crls;
    }
    
    ret = sk_X509_CRL_push(crls, crl);
    if(ret < 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "sk_X509_CRL_push");
	return(-1);	
    }
        
    return(0);
}

X509_CRL* 
xmlSecOpenSSLKeyDataX509GetCrl(xmlSecKeyDataPtr data, size_t pos) {
    STACK_OF(X509_CRL)* crls;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), NULL);

    crls = xmlSecOpenSSLKeyDataX509GetAllCrls(data);
    xmlSecAssert2(crls != NULL, NULL);
    xmlSecAssert2((int)pos < sk_X509_CRL_num(crls), NULL);

    return(sk_X509_CRL_value(crls, pos));
}

size_t 
xmlSecOpenSSLKeyDataX509GetCrlsNumber(xmlSecKeyDataPtr data) {
    STACK_OF(X509_CRL)* crls;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), 0);

    crls = xmlSecOpenSSLKeyDataX509GetAllCrls(data);
    return((crls != NULL) ? sk_X509_CRL_num(crls) : 0);
}

static int	
xmlSecOpenSSLKeyDataX509Initialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);

    return(0);
}

static int
xmlSecOpenSSLKeyDataX509Duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    X509* certSrc;
    X509* certDst;
    X509_CRL* crlSrc;
    X509_CRL* crlDst;
    size_t size, pos;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataX509Id), -1);
    
    /* copy certs */
    size = xmlSecOpenSSLKeyDataX509GetCertsNumber(src);
    for(pos = 0; pos < size; ++pos) {
	certSrc = xmlSecOpenSSLKeyDataX509GetCert(src, pos);
	if(certSrc == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataX509GetCert(%d)", pos);
	    return(-1);
	}
	
	certDst = X509_dup(certSrc);
	if(certDst == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"X509_dup");
	    return(-1);
	}
	
	ret = xmlSecOpenSSLKeyDataX509AdoptCert(dst, certDst);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataX509AdoptCert");
	    X509_free(certDst);
	    return(-1);
	}
    }

    /* copy crls */
    size = xmlSecOpenSSLKeyDataX509GetCrlsNumber(src);
    for(pos = 0; pos < size; ++pos) {
	crlSrc = xmlSecOpenSSLKeyDataX509GetCrl(src, pos);
	if(crlSrc == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataX509GetCrl(%d)", pos);
	    return(-1);
	}
	
	crlDst = X509_CRL_dup(crlSrc);
	if(crlDst == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"X509_CRL_dup");
	    return(-1);
	}
	
	ret = xmlSecOpenSSLKeyDataX509AdoptCrl(dst, crlDst);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataX509AdoptCrl");
	    X509_CRL_free(crlDst);
	    return(-1);
	}
    }

    /* copy verified cert if exist */
    certSrc = xmlSecOpenSSLKeyDataX509GetVerified(src);
    if(certSrc != NULL) {
	certDst = X509_dup(certSrc);
	if(certDst == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"X509_dup");
	    return(-1);
	}
	ret = xmlSecOpenSSLKeyDataX509AdoptVerified(dst, certDst);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataX509AdoptVerified");
	    X509_free(certDst);
	    return(-1);
	}
    }
    
    /* 
     * we don't copy verified cert subject because we can 
     * re-initialize it from verified cert if needed
     */
    return(0);
}

static void
xmlSecOpenSSLKeyDataX509Finalize(xmlSecKeyDataPtr data) {
    STACK_OF(X509)* certs;
    STACK_OF(X509_CRL)* crls;
    X509* cert;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id));

    certs = xmlSecOpenSSLKeyDataX509GetAllCerts(data);
    if(certs != NULL) {
	sk_X509_pop_free(certs, X509_free); 	
    }

    crls = xmlSecOpenSSLKeyDataX509GetAllCrls(data);
    if(crls != NULL) {
	sk_X509_CRL_pop_free(crls, X509_CRL_free); 	
    }

    cert = xmlSecOpenSSLKeyDataX509GetVerified(data);
    if(cert != NULL) {
	X509_free(cert);
    }
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyEnsureData(xmlSecOpenSSLKeyDataX509Id)");
	return(-1);
    }
    
    ret = xmlSecOpenSSLX509DataNodeRead(data, node, keyInfoCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLX509DataNodeRead");
	return(-1);
    }

    ret = xmlSecOpenSSLKeyDataX509VerifyAndExtractKey(data, key, keyInfoCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataX509VerifyAndExtractKey");
	return(-1);
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
    size_t size, pos;
    				
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
    size = xmlSecOpenSSLKeyDataX509GetCertsNumber(data);
    for(pos = 0; pos < size; ++pos) {
	cert = xmlSecOpenSSLKeyDataX509GetCert(data, pos);
	if(cert == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataX509GetCert(%d)", pos);
	    return(-1);
	}
	
	/* todo: set base64 size from context */
	buf = xmlSecOpenSSLX509CertBase64DerWrite(cert, 60); 
	if(buf == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecX509DataWriteDerCert");
	    return(-1);
	}
	
	cur = xmlSecAddChild(node, BAD_CAST "X509Certificate", xmlSecDSigNs);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(\"X509Certificate\")");    
	    xmlFree(buf);
	    return(-1);	
	}
	/* todo: add \n around base64 data - from context */
	/* todo: add errors check */
	xmlNodeSetContent(cur, BAD_CAST "\n");
	xmlNodeSetContent(cur, buf);
	xmlFree(buf);
    }    

    /* write crls */
    size = xmlSecOpenSSLKeyDataX509GetCrlsNumber(data);
    for(pos = 0; pos < size; ++pos) {
	crl = xmlSecOpenSSLKeyDataX509GetCrl(data, pos);
	if(crl == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataX509GetCrl(%d)", pos);
	    return(-1);
	}
	
	/* todo: set base64 size from context */
	buf = xmlSecOpenSSLX509CrlBase64DerWrite(crl, 60); 
	if(buf == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLX509CrlBase64DerWrite");
	    return(-1);
	}
	
	cur = xmlSecAddChild(node, BAD_CAST "X509CRL", xmlSecDSigNs);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(\"X509CRL\")");    
	    xmlFree(buf);
	    return(-1);	
	}
	/* todo: add \n around base64 data - from context */
	/* todo: add errors check */
	xmlNodeSetContent(cur, BAD_CAST "\n");
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
    size_t size, pos;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== X509 Data:\n");
    cert = xmlSecOpenSSLKeyDataX509GetVerifiedCert(data);
    if(cert != NULL) {
	fprintf(output, "==== Verified Certificate:\n");
	xmlSecOpenSSLX509CertDebugDump(cert, output);
    }
    
    size = xmlSecOpenSSLKeyDataX509GetCertsNumber(data);
    for(pos = 0; pos < size; ++pos) {
	cert = xmlSecOpenSSLKeyDataX509GetCert(data, pos);
	if(cert == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataX509GetCert(%d)", pos);
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
    size_t size, pos;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<X509Data>\n");
    cert = xmlSecOpenSSLKeyDataX509GetVerifiedCert(data);
    if(cert != NULL) {
	fprintf(output, "<VerifiedCertificate>\n");
	xmlSecOpenSSLX509CertDebugXmlDump(cert, output);
	fprintf(output, "</VerifiedCertificate>\n");
    }
    
    size = xmlSecOpenSSLKeyDataX509GetCertsNumber(data);
    for(pos = 0; pos < size; ++pos) {
	cert = xmlSecOpenSSLKeyDataX509GetCert(data, pos);
	if(cert == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataX509GetCert(%d)", pos);
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
	if(xmlSecCheckNodeName(cur, BAD_CAST "X509Certificate", xmlSecDSigNs)) {
	    ret = xmlSecOpenSSLX509CertificateNodeRead(data, cur, keyInfoCtx);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509SubjectName", xmlSecDSigNs)) {
	    ret = xmlSecOpenSSLX509SubjectNameNodeRead(data, cur, keyInfoCtx);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509IssuerSerial", xmlSecDSigNs)) {
	    ret = xmlSecOpenSSLX509IssuerSerialNodeRead(data, cur, keyInfoCtx);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509SKI", xmlSecDSigNs)) {
	    ret = xmlSecOpenSSLX509SKINodeRead(data, cur, keyInfoCtx);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509CRL", xmlSecDSigNs)) {
	    ret = xmlSecOpenSSLX509CRLNodeRead(data, cur, keyInfoCtx);
	} else if(0) {
	    /* todo: laxi schema validation: ignore unknown nodes */	    
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_INVALID_NODE,
			"name=\"%s\"", cur->name);
	    return(-1);
	}
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"%d", ret);
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
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509Certificate");
	return(-1);
    }

    cert = xmlSecOpenSSLX509CertBase64DerRead(content);
    if(cert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLX509CertBase64DerRead");
	xmlFree(content);
	return(-1);
    }    
    
    ret = xmlSecOpenSSLKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataX509AdoptCert");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeysMngrGetDataStore(xmlSecOpenSSLX509StoreId)");
	return(-1);
    }

    subject = xmlNodeGetContent(node);
    if(subject == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509Subject");
	return(-1);
    }

    cert = xmlSecOpenSSLX509StoreFindCert(x509Store, subject, NULL, NULL, NULL, keyInfoCtx);
    if(cert == NULL){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CERT_NOT_FOUND,
		    " ");
	xmlFree(subject);
	return((keyInfoCtx->failIfCertNotFound) ? -1 : 0);
    }

    cert2 = X509_dup(cert);
    if(cert2 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_dup");
	xmlFree(subject);
	return(-1);
    }
    
    ret = xmlSecOpenSSLKeyDataX509AdoptCert(data, cert2);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataX509AdoptCert");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeysMngrGetDataStore(xmlSecOpenSSLX509StoreId)");
	return(-1);
    }

    cur = xmlSecGetNextElementNode(node->children);

    /* the first is required node X509IssuerName */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, BAD_CAST "X509IssuerName", xmlSecDSigNs)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    "X509IssuerName");
	return(-1);
    }    
    issuerName = xmlNodeGetContent(cur);
    if(issuerName == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509IssuerName");    
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next); 

    /* next is required node X509SerialNumber */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, BAD_CAST "X509SerialNumber", xmlSecDSigNs)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    "X509SerialNumber");
	xmlFree(issuerName);
	return(-1);
    }    
    issuerSerial = xmlNodeGetContent(cur);
    if(issuerSerial == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509SerialNumber");
	xmlFree(issuerName);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next); 

    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    (cur->name != NULL) ? (char*)cur->name : "NULL");
	xmlFree(issuerSerial);
	xmlFree(issuerName);
	return(-1);
    }

    cert = xmlSecOpenSSLX509StoreFindCert(x509Store, NULL, issuerName, issuerSerial, NULL, keyInfoCtx);
    if(cert == NULL){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CERT_NOT_FOUND,
		    " ");
	xmlFree(issuerSerial);
	xmlFree(issuerName);
	return((keyInfoCtx->failIfCertNotFound) ? -1 : 0);    
    }

    cert2 = X509_dup(cert);
    if(cert2 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_dup");
	xmlFree(issuerSerial);
	xmlFree(issuerName);
	return(-1);
    }

    ret = xmlSecOpenSSLKeyDataX509AdoptCert(data, cert2);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataX509AdoptCert");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeysMngrGetDataStore(xmlSecOpenSSLX509StoreId)");
	return(-1);
    }
    
    ski = xmlNodeGetContent(node);
    if(ski == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509SKI");
	return(-1);
    }

    cert = xmlSecOpenSSLX509StoreFindCert(x509Store, NULL, NULL, NULL, ski, keyInfoCtx);
    if(cert == NULL){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CERT_NOT_FOUND,
		    " ");
	xmlFree(ski);
	return((keyInfoCtx->failIfCertNotFound) ? -1 : 0);    
    }

    cert2 = X509_dup(cert);
    if(cert2 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_dup");
	xmlFree(ski);
	return(-1);
    }

    ret = xmlSecOpenSSLKeyDataX509AdoptCert(data, cert2);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataX509AdoptCert");
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
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509Certificate");
	return(-1);
    }

    crl = xmlSecOpenSSLX509CrlBase64DerRead(content);
    if(crl == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLX509CrlBase64DerRead");
	xmlFree(content);
	return(-1);
    }    
    
    ret = xmlSecOpenSSLKeyDataX509AdoptCrl(data, crl);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataX509AdoptCrl");
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
    xmlSecKeyDataStorePtr x509Store;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataX509Id), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecOpenSSLX509StoreId);
    if(x509Store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeysMngrGetDataStore(xmlSecOpenSSLX509StoreId)");
	return(-1);
    }

    /* todo: ctx flag to read certs w/o verification */
    if((xmlSecOpenSSLKeyDataX509GetVerifiedCert(data) == NULL) &&
       (xmlSecOpenSSLKeyDataX509GetAllCerts(data) != NULL) &&
       (xmlSecKeyGetValue(key) == NULL)) {
       
	X509* verifiedCert;

	verifiedCert = xmlSecOpenSSLX509StoreVerify(x509Store,
			    xmlSecOpenSSLKeyDataX509GetAllCerts(data),
			    xmlSecOpenSSLKeyDataX509GetAllCrls(data),
			    keyInfoCtx);
	if(verifiedCert != NULL) {
	    xmlSecKeyDataPtr keyValue;
	    X509* cert;
	    
	    cert = X509_dup(verifiedCert);
	    if(cert == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "X509_dup");
		return(-1);
	    }
	    ret = xmlSecOpenSSLKeyDataX509AdoptVerified(data, cert);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLKeyDataX509AdoptVerified");
		X509_free(cert);
		return(-1);
	    }
	
	    keyValue = xmlSecOpenSSLX509CertGetKey(verifiedCert);
	    if(keyValue == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLX509CertGetKey");
		return(-1);
	    }
	    
	    /* todo: verify that the key matches our expectations */
	    
	    ret = xmlSecKeySetValue(key, keyValue);
    	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecKeySetValue");
		return(-1);
	    }	    
	}	
    }
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
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_get_pubkey");
	return(NULL);
    }    

    data = xmlSecOpenSSLEvpKeyAdopt(pKey);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLEvpKeyAdopt");
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
    ret = xmlSecBase64Decode(buf, (unsigned char*)buf, xmlStrlen(buf)); 
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Decode - %d", ret);
	return(NULL);
    }
    
    return(xmlSecOpenSSLX509CertDerRead((unsigned char*)buf, ret));
}

static X509*
xmlSecOpenSSLX509CertDerRead(const unsigned char* buf, size_t size) {
    X509 *cert = NULL;
    BIO *mem = NULL;
    int ret;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);
    
    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_new(BIO_s_mem)");
	return(NULL);
    }
    
    ret = BIO_write(mem, buf, size);
    if(ret <= 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_write(BIO_s_mem)");
	BIO_free_all(mem);
	return(NULL);
    }

    cert = d2i_X509_bio(mem, NULL);
    if(cert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "d2i_X509_bio");
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
    unsigned char *p = NULL;
    long size;

    xmlSecAssert2(cert != NULL, NULL);
	
    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_new(BIO_s_mem)");
	return(NULL);
    }

    /* todo: add error checks */
    i2d_X509_bio(mem, cert);
    BIO_flush(mem);
        
    size = BIO_get_mem_data(mem, &p);
    if((size <= 0) || (p == NULL)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_get_mem_data");
	BIO_free_all(mem);
	return(NULL);
    }
    
    res = xmlSecBase64Encode(p, size, base64LineWrap);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Encode");
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
    ret = xmlSecBase64Decode(buf, (unsigned char*)buf, xmlStrlen(buf)); 
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Decode - %d", ret);
	return(NULL);
    }
    
    return(xmlSecOpenSSLX509CrlDerRead((unsigned char*)buf, ret));
}

static X509_CRL*
xmlSecOpenSSLX509CrlDerRead(unsigned char* buf, size_t size) {
    X509_CRL *crl = NULL;
    BIO *mem = NULL;
    int ret;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);
    
    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_new(BIO_s_mem)");
	return(NULL);
    }
    
    ret = BIO_write(mem, buf, size);
    if(ret <= 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_write(BIO_s_mem)");
	BIO_free_all(mem);
	return(NULL);
    }

    crl = d2i_X509_CRL_bio(mem, NULL);
    if(crl == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "d2i_X509_bio");
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
    unsigned char *p = NULL;
    long size;

    xmlSecAssert2(crl != NULL, NULL);
	
    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_new(BIO_s_mem)");
	return(NULL);
    }

    /* todo: add error checks */
    i2d_X509_CRL_bio(mem, crl);
    BIO_flush(mem);
        
    size = BIO_get_mem_data(mem, &p);
    if((size <= 0) || (p == NULL)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_get_mem_data");
	BIO_free_all(mem);
	return(NULL);
    }
    
    res = xmlSecBase64Encode(p, size, base64LineWrap);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Encode");
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
								 const unsigned char* buf,
								 size_t bufSize,
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
};

xmlSecKeyDataId 
xmlSecOpenSSLKeyDataRawX509CertGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataRawX509CertKlass);
}

static int
xmlSecOpenSSLKeyDataRawX509CertBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    const unsigned char* buf, size_t bufSize,
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLX509CertDerRead");
	return(-1);
    }

    data = xmlSecKeyEnsureData(key, xmlSecOpenSSLKeyDataX509Id);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataInitialize(xmlSecOpenSSLKeyDataX509Id)");
	X509_free(cert);
	return(-1);
    }
    
    ret = xmlSecOpenSSLKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataX509AdoptCert");
	X509_free(cert);
	return(-1);
    }

    ret = xmlSecOpenSSLKeyDataX509VerifyAndExtractKey(data, key, keyInfoCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataX509AdoptCert");
	return(-1);
    }
    return(0);
}

#endif /* XMLSEC_NO_X509 */
