/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#include "globals.h"

#include <string.h>

#include <windows.h>
#include <wincrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscrypto/certkeys.h>
#include <xmlsec/mscrypto/crypto.h>

/**************************************************************************
 *
 * Internal MSCrypto PCCERT_CONTEXT key CTX
 *
 *************************************************************************/
typedef struct _xmlSecMSCryptoKeyDataCtx xmlSecMSCryptoKeyDataCtx, 
						*xmlSecMSCryptoKeyDataCtxPtr;
/*
 * Since MSCrypto does not provide direct handles to private keys, we support
 * only private keys linked to a certificate context. The certificate context
 * also provides the public key. Only when no certificate context is used, and
 * a public key from xml document is provided, we need HCRYPTKEY.... The focus
 * now is however directed to certificates.  Wouter
 */
struct _xmlSecMSCryptoKeyDataCtx {
    PCCERT_CONTEXT pCert;
    /* Currently not used, however added for future support 
     * for keypairs without certificates */
    /*
    HCRYPTKEY	hPubKey;
    HCRYPTKEY	hPrivKey; 
    */
};	    

/******************************************************************************
 *
 * xmlSecMSCryptoKeyDataCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecMSCryptoKeyDataSize	\
    (sizeof(xmlSecKeyData) + sizeof(xmlSecMSCryptoKeyDataCtx))	
#define xmlSecMSCryptoKeyDataGetCtx(data) \
    ((xmlSecMSCryptoKeyDataCtxPtr)(((xmlSecByte*)(data)) + sizeof(xmlSecKeyData)))

static int		xmlSecMSCryptoKeyDataInitialize	(xmlSecKeyDataPtr data);
int     		xmlSecMSCryptoKeyDataDuplicate	(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src);
static void		xmlSecMSCryptoKeyDataFinalize	(xmlSecKeyDataPtr data);
static int		xmlSecMSCryptoKeyDataGetSize	(xmlSecKeyDataPtr data);

/**
 * xmlSecMSCryptoKeyDataAdoptCert:
 * @data:		the pointer to MSCrypto pccert data.
 * @pCert:		the pointer to PCCERT key.
 *
 * Sets the value of key data.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecMSCryptoKeyDataAdoptCert(xmlSecKeyDataPtr data, PCCERT_CONTEXT pCert) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), -1);
    xmlSecAssert2(pCert != NULL, -1);
    
    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    
    if(ctx->pCert != NULL) {
		CertFreeCertificateContext(ctx->pCert);
    }

    /* TODO: SHouldn't we make a copy here? */
    ctx->pCert = pCert;
    return(0);
}

/**
 * xmlSecMSCryptoKeyDataGetCert:
 * @data:		the pointer to MS Crypto PCCERT_CONTEXT data.
 *
 * Gets the PCCERT_CONTEXT from the key data.
 *
 * Returns pointer to PCCERT_CONTEXT or NULL if an error occurs.
 */
PCCERT_CONTEXT 
xmlSecMSCryptoKeyDataGetCert(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), NULL);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->pCert);
}

static int 
xmlSecMSCryptoKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), -1);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCryptoKeyDataCtx));

    return(0);
}

int 
xmlSecMSCryptoKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecMSCryptoKeyDataCtxPtr ctxDst;
    xmlSecMSCryptoKeyDataCtxPtr ctxSrc;

    xmlSecAssert2(xmlSecKeyDataIsValid(dst), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(dst, xmlSecMSCryptoKeyDataSize), -1);
    xmlSecAssert2(xmlSecKeyDataIsValid(src), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(src, xmlSecMSCryptoKeyDataSize), -1);

    ctxDst = xmlSecMSCryptoKeyDataGetCtx(dst);
    xmlSecAssert2(ctxDst != NULL, -1);
    xmlSecAssert2(ctxDst->pCert == NULL, -1);

    ctxSrc = xmlSecMSCryptoKeyDataGetCtx(src);
    xmlSecAssert2(ctxSrc != NULL, -1);

    if(ctxSrc->pCert != NULL) {
	ctxDst->pCert = xmlSecMSCryptoCertDup(ctxSrc->pCert);
	if(ctxDst->pCert == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"xmlSecMSCryptoPCCDup",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    } 

    return(0);
}

static void 
xmlSecMSCryptoKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    
    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize));

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert(ctx != NULL);
    
    if(ctx->pCert != NULL) {
	CertFreeCertificateContext(ctx->pCert);
	ctx->pCert = NULL;
    }

    memset(ctx, 0, sizeof(xmlSecMSCryptoKeyDataCtx));
}

static int 
xmlSecMSCryptoKeyDataGetSize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), 0);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    if(ctx->pCert != NULL) {
	return (CertGetPublicKeyLength(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
		&(ctx->pCert->pCertInfo->SubjectPublicKeyInfo)));
    }
    
    /* TODO: Implement getting size from HKEY */
    return (0);
}

/**
 * xmlSecMSCryptoCertDup:
 *
 * Returns pointer to newly created PCCERT_CONTEXT object or NULL if an error occurs.
 */
PCCERT_CONTEXT xmlSecMSCryptoCertDup(PCCERT_CONTEXT pCert) {
    PCCERT_CONTEXT ret;

    xmlSecAssert2(pCert != NULL, NULL);

    ret = CertDuplicateCertificateContext(pCert);
    if(ret == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "CertDuplicateCertificateContext",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);		    	
    }
    
    return(ret);
}

/**
 * xmlSecMSCryptoCertAdopt:
 *
 * Returns pointer to newly created xmlsec key or NULL if an error occurs.
 */
xmlSecKeyDataPtr xmlSecMSCryptoCertAdopt(PCCERT_CONTEXT pCert) {
    xmlSecKeyDataPtr data = NULL;
    int ret;
    
    xmlSecAssert2(pCert != NULL, NULL);

#ifndef XMLSEC_NO_RSA
    if (!strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_RSA_RSA)) {
	data = xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataRsaId);
	if(data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeyDataCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecMSCryptoPCCDataRsaId");
	    return(NULL);	    
	}
    }
#endif /* XMLSEC_NO_RSA */	
/*
#ifndef XMLSEC_NO_DSA
	if (!strcmp(pCert->pCertInfo->SubjectPublicKeyInfo->Algorithm.pszObjId, szOID_DSA)) {
		data = xmlSecKeyDataCreate(xmlSecMSCryptoPCCDataDsaId);
		if(data == NULL) {
			xmlSecError(XMLSEC_ERRORS_HERE,
				NULL,
				"xmlSecKeyDataCreate",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecMSCryptoPCCDataDsaId");
			return(NULL);	    
		}
	}
#endif *//* XMLSEC_NO_DSA */	
	if (NULL == data) {
		xmlSecError(XMLSEC_ERRORS_HERE,
				NULL,
				NULL,
				XMLSEC_ERRORS_R_INVALID_TYPE,
				"PCCERT_CONTEXT key type %s not supported", pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
		return(NULL);
    }

    xmlSecAssert2(data != NULL, NULL);    
    ret = xmlSecMSCryptoKeyDataAdoptCert(data, pCert);
    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
				NULL,
				"xmlSecMSCryptoPCCDataAdoptPCC",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				XMLSEC_ERRORS_NO_MESSAGE);
		xmlSecKeyDataDestroy(data);
		return(NULL);	    
    }
    return(data);
}



#ifndef XMLSEC_NO_RSA
/**************************************************************************
 *
 * <dsig:RSAKeyValue> processing
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-RSAKeyValue
 * The RSAKeyValue Element
 *
 * RSA key values have two fields: Modulus and Exponent.
 *
 * <RSAKeyValue>
 *   <Modulus>xA7SEU+e0yQH5rm9kbCDN9o3aPIo7HbP7tX6WOocLZAtNfyxSZDU16ksL6W
 *     jubafOqNEpcwR3RdFsT7bCqnXPBe5ELh5u4VEy19MzxkXRgrMvavzyBpVRgBUwUlV
 *   	  5foK5hhmbktQhyNdy/6LpQRhDUDsTvK+g9Ucj47es9AQJ3U=
 *   </Modulus>
 *   <Exponent>AQAB</Exponent>
 * </RSAKeyValue>
 *
 * Arbitrary-length integers (e.g. "bignums" such as RSA moduli) are 
 * represented in XML as octet strings as defined by the ds:CryptoBinary type.
 *
 * Schema Definition:
 * 
 * <element name="RSAKeyValue" type="ds:RSAKeyValueType"/>
 * <complexType name="RSAKeyValueType">
 *   <sequence>
 *     <element name="Modulus" type="ds:CryptoBinary"/> 
 *     <element name="Exponent" type="ds:CryptoBinary"/>
 *   </sequence>
 * </complexType>
 *
 * DTD Definition:
 * 
 * <!ELEMENT RSAKeyValue (Modulus, Exponent) > 
 * <!ELEMENT Modulus (#PCDATA) >
 * <!ELEMENT Exponent (#PCDATA) >
 *
 * ============================================================================
 * 
 *
 *************************************************************************/

static int      xmlSecMSCryptoKeyDataRsaInitialize(xmlSecKeyDataPtr data);
static int      xmlSecMSCryptoKeyDataRsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src);
static void	xmlSecMSCryptoKeyDataRsaFinalize(xmlSecKeyDataPtr data);
static int      xmlSecMSCryptoKeyDataRsaXmlRead(xmlSecKeyDataId id,
		        			xmlSecKeyPtr key,
						xmlNodePtr node,
						xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecMSCryptoKeyDataRsaXmlWrite(xmlSecKeyDataId id,
		        			 xmlSecKeyPtr key,
					         xmlNodePtr node,
                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecMSCryptoKeyDataRsaGenerate(xmlSecKeyDataPtr data,
					         xmlSecSize sizeBits,
					         xmlSecKeyDataType type);

static xmlSecKeyDataType    xmlSecMSCryptoKeyDataRsaGetType(xmlSecKeyDataPtr data);
static xmlSecSize           xmlSecMSCryptoKeyDataRsaGetSize(xmlSecKeyDataPtr data);
static void	            xmlSecMSCryptoKeyDataRsaDebugDump(xmlSecKeyDataPtr data, FILE* output);
static void	            xmlSecMSCryptoKeyDataRsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output);

static xmlSecKeyDataKlass xmlSecMSCryptoKeyDataRsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCryptoKeyDataSize,

    /* data */
    xmlSecNameRSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefRSAKeyValue,			/* const xmlChar* href; */
    xmlSecNodeRSAKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecDSigNs,				/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecMSCryptoKeyDataRsaInitialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCryptoKeyDataRsaDuplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCryptoKeyDataRsaFinalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecMSCryptoKeyDataRsaGenerate,		/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecMSCryptoKeyDataRsaGetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecMSCryptoKeyDataRsaGetSize,		/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    xmlSecMSCryptoKeyDataRsaXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecMSCryptoKeyDataRsaXmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,					/* xmlSecKeyDataBinReadMethod binRead; */
    NULL,					/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCryptoKeyDataRsaDebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCryptoKeyDataRsaDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecMSCryptoKeyDataRsaGetKlass:
 *
 * The MSCrypto RSA CertKey data klass.
 *
 * Returns pointer to MSCrypto RSA key data klass.
 */
xmlSecKeyDataId 
xmlSecMSCryptoKeyDataRsaGetKlass(void) {
    return(&xmlSecMSCryptoKeyDataRsaKlass);
}

/** 
 * xmlSecMSCryptoKeyDataRsaAdoptCert:
 * @data:		the pointer to RSA key data.
 * @pCert:		the pointer to PCCERT_CONTEXT.
 *
 * Sets the RSA key data value to PCCERT_CONTEXT.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecMSCryptoKeyDataRsaAdoptCert(xmlSecKeyDataPtr data, PCCERT_CONTEXT pCert) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataRsaId), -1);
    xmlSecAssert2(pCert != NULL, -1);
	/* TODO: Replace this with some MSCrypto check */
    //xmlSecAssert2(pKey->type == EVP_PKEY_RSA, -1);
    
    return(xmlSecMSCryptoKeyDataAdoptCert(data, pCert));
}

/**
 * xmlSecMSCryptoKeyDataRsaGetCert:
 * @data:		the pointer to RSA key data.
 *
 * Gets the PCCERT_CONTEXT from RSA key data.
 *
 * Returns pointer to PCCERT_CONTEXT or NULL if an error occurs.
 */
PCCERT_CONTEXT 
xmlSecMSCryptoKeyDataRsaGetCert(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataRsaId), NULL);

    return(xmlSecMSCryptoKeyDataGetCert(data));
}

static int 
xmlSecMSCryptoKeyDataRsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataRsaId), -1);

    return(xmlSecMSCryptoKeyDataInitialize(data));
}

static int 
xmlSecMSCryptoKeyDataRsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCryptoKeyDataRsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCryptoKeyDataRsaId), -1);

    return(xmlSecMSCryptoKeyDataDuplicate(dst, src));
}

static void 
xmlSecMSCryptoKeyDataRsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataRsaId));

    xmlSecMSCryptoKeyDataFinalize(data);
}

static int 
xmlSecMSCryptoKeyDataRsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
    				xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
	return(-1);
}

static int 
xmlSecMSCryptoKeyDataRsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
	return(-1);	
}

static int 
xmlSecMSCryptoKeyDataRsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, 
				xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
	return(-1);
}

static xmlSecKeyDataType 
xmlSecMSCryptoKeyDataRsaGetType(xmlSecKeyDataPtr data) {
	xmlSecMSCryptoKeyDataCtxPtr ctx;
    
    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, xmlSecKeyDataTypeUnknown);

    if (ctx->pCert != NULL) {
	if (TRUE == CryptFindCertificateKeyProvInfo(ctx->pCert, 0, NULL)) {
	    return(xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
	} else {
	    return(xmlSecKeyDataTypePublic);
	}
    }

    return(xmlSecKeyDataTypeUnknown);
}

static xmlSecSize 
xmlSecMSCryptoKeyDataRsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataRsaId), 0);

    return (xmlSecMSCryptoKeyDataGetSize(data));
}

static void 
xmlSecMSCryptoKeyDataRsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataRsaId));
    xmlSecAssert(output != NULL);
    
    fprintf(output, "=== rsa key: size = %d\n", 
	    xmlSecMSCryptoKeyDataRsaGetSize(data));
}

static void xmlSecMSCryptoKeyDataRsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataRsaId));
    xmlSecAssert(output != NULL);
        
    fprintf(output, "<RSAKeyValue size=\"%d\" />\n", 
	    xmlSecMSCryptoKeyDataRsaGetSize(data));
}
    
#endif /* XMLSEC_NO_RSA */


