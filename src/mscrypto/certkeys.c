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
#include <xmlsec/mscrypto/bignum.h>

#define XMLSEC_CONTAINER_NAME "xmlsec-key-container"

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
    HCRYPTPROV hProv;
    LPCTSTR providerName;
    DWORD providerType;
    BOOL fCallerFreeProv;
    PCCERT_CONTEXT pCert;
    DWORD dwKeySpec;
    HCRYPTKEY hKey;
    xmlSecKeyDataType type;
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
static int 
xmlSecMSCryptoKeyDataAdoptCert(xmlSecKeyDataPtr data, PCCERT_CONTEXT pCert, xmlSecKeyDataType type) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), -1);
    xmlSecAssert2(pCert != NULL, -1);
    xmlSecAssert2(type & (xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate), -1);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    if (ctx->hKey != 0) {
	CryptDestroyKey(ctx->hKey);
	ctx->hKey = 0;
    }

    if(ctx->pCert != NULL) {
	CertFreeCertificateContext(ctx->pCert);
    }

    if ((ctx->hProv != 0) && (ctx->fCallerFreeProv)) {
	CryptReleaseContext(ctx->hProv, 0);
	ctx->hProv = 0;
    }

    ctx->pCert = pCert;
    ctx->type = type;

    /* Now we acquire a context for this key(pair). The context is needed
     * for the real crypto stuff in MS Crypto.
     */
    if (type & xmlSecKeyDataTypePrivate) {
        if (!CryptAcquireCertificatePrivateKey(ctx->pCert, 
					       CRYPT_ACQUIRE_USE_PROV_INFO_FLAG, 
					       NULL, 
					       &(ctx->hProv), 
					       &(ctx->dwKeySpec), 
					       &(ctx->fCallerFreeProv))) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"CryptAcquireCertificatePrivateKey",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"error code=%d", GetLastError());
	    return(-1);
	}
    } else if (type & xmlSecKeyDataTypePublic) {
	if (!CryptAcquireContext(&(ctx->hProv), 
				 NULL, 
				 ctx->providerName, 
				 ctx->providerType, 
				 CRYPT_VERIFYCONTEXT)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"CryptAcquireContext",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"error code=%d", GetLastError());
	    return(-1);
	}
	ctx->dwKeySpec = 0;
	ctx->fCallerFreeProv = TRUE;
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "Unsupported keytype");
	return(0);
    }

    /* CryptImportPublicKeyInfo is only needed when a real key handle
     * is needed. The key handle is needed for de/encrypting and for
     * verifying of a signature, *not* for signing. We could call
     * CryptImportPublicKeyInfo in xmlSecMSCryptoKeyDataGetKey instead
     * so no unnessecary calls to CryptImportPublicKeyInfo are being
     * made. WK
     */
    if (!CryptImportPublicKeyInfo(ctx->hProv, 
	X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
	&(ctx->pCert->pCertInfo->SubjectPublicKeyInfo), 
	&(ctx->hKey))) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"CryptImportPublicKeyInfo",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"error code=%d", GetLastError());
	    CryptReleaseContext(ctx->hProv, 0);
	    ctx->hProv = 0;
	    return(-1);
    }

    return(0);
}

static int 
xmlSecMSCryptoKeyDataAdoptKey(xmlSecKeyDataPtr data, 
			      HCRYPTPROV hProv,
			      BOOL fCallerFreeProv,
			      HCRYPTKEY hKey, 
			      DWORD dwKeySpec,
			      xmlSecKeyDataType type) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), -1);
    xmlSecAssert2(hKey != 0, -1);
    xmlSecAssert2(type & (xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate), -1);
    
    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    if(ctx->hKey != 0) {
	CryptDestroyKey(ctx->hKey);
    }
    if(ctx->pCert != NULL) {
	CertFreeCertificateContext(ctx->pCert);
	ctx->pCert = NULL;
    }
    if (ctx->hProv != 0 && ctx->fCallerFreeProv) {
	CryptReleaseContext(ctx->hProv, 0);
    }

    ctx->hProv = hProv;
    ctx->fCallerFreeProv = fCallerFreeProv;
    ctx->dwKeySpec = dwKeySpec;
    ctx->hKey = hKey;
    ctx->type = type;

    return(0);
}

HCRYPTKEY
xmlSecMSCryptoKeyDataGetKey(xmlSecKeyDataPtr data, xmlSecKeyDataType type) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), 0);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);
 
    return(ctx->hKey);
}

HCRYPTPROV
xmlSecMSCryptoKeyDataGetMSCryptoProvider(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), 0);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return(ctx->hProv);
}

DWORD
xmlSecMSCryptoKeyDataGetMSCryptoKeySpec(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), 0);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return(ctx->dwKeySpec);
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

    if (ctxSrc->hKey != 0) {
	if (!CryptDuplicateKey(ctxSrc->hKey, NULL, 0, &(ctxDst->hKey))) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"CryptDuplicateKey",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }
    if (ctxSrc->hProv != 0) {
	/* What to do when fCallerFreeProv == FALSE ???, add reference or not? */
	CryptContextAddRef(ctxSrc->hProv, NULL, 0);
    }

    ctxDst->hProv = ctxSrc->hProv;
    ctxDst->fCallerFreeProv = ctxSrc->fCallerFreeProv;
    ctxDst->dwKeySpec = ctxSrc->dwKeySpec;
    ctxDst->providerName = ctxSrc->providerName;
    ctxDst->providerType = ctxSrc->providerType;
    ctxDst->type = ctxSrc->type;

    return(0);
}

static void 
xmlSecMSCryptoKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    
    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize));

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert(ctx != NULL);
    
    if (ctx->hKey != 0) {
	CryptDestroyKey(ctx->hKey);
    }
    if(ctx->pCert != NULL) {
	CertFreeCertificateContext(ctx->pCert);
    }
    if (ctx->hProv != 0 && ctx->fCallerFreeProv) {
	CryptReleaseContext(ctx->hProv, 0);
    }

    memset(ctx, 0, sizeof(xmlSecMSCryptoKeyDataCtx));
}

static int 
xmlSecMSCryptoKeyDataGetSize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    DWORD length = 0;
    DWORD lenlen = sizeof(DWORD);

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), 0);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    if(ctx->pCert != NULL) {
	return (CertGetPublicKeyLength(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
		&(ctx->pCert->pCertInfo->SubjectPublicKeyInfo)));
    } else if (ctx->hKey != 0) {
	if (!CryptGetKeyParam(ctx->hKey, KP_KEYLEN, (BYTE *)&length, &lenlen, 0)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"CertDuplicateCertificateContext",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"Error no: %d", GetLastError());
	    return(0);
	}
	return(length);
    }
    
    return (0);
}

static xmlSecKeyDataType 
xmlSecMSCryptoKeyDataGetType(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    
    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, xmlSecKeyDataTypeUnknown);

    /* We could make a call to CryptFindCertificateKeyProvInfo here, to find out if
     * we *really* have a private key or not. However if the certificate is not 
     * linked to a private key, the call takes an ridiculous amount of time.
     * the way it is now is better I think. WK.
     */
    return(ctx->type);
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
xmlSecKeyDataPtr 
xmlSecMSCryptoCertAdopt(PCCERT_CONTEXT pCert, xmlSecKeyDataType type) {
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
			"xmlSecMSCryptoDataRsaId");
	    return(NULL);	    
	}
    }
#endif /* XMLSEC_NO_RSA */	

#ifndef XMLSEC_NO_DSA
	if (!strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_X957_DSA /*szOID_DSALG_SIGN*/)) {
		data = xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataDsaId);
		if(data == NULL) {
			xmlSecError(XMLSEC_ERRORS_HERE,
				NULL,
				"xmlSecKeyDataCreate",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecMSCryptoKeyDataDsaId");
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
    ret = xmlSecMSCryptoKeyDataAdoptCert(data, pCert, type);
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

static int 
xmlSecMSCryptoKeyDataRsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    
    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), xmlSecKeyDataTypeUnknown);

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataRsaId), -1);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCryptoKeyDataCtx));

    ctx->providerName = MS_ENHANCED_PROV;
    ctx->providerType = PROV_RSA_FULL;
    
    return(0);
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
    
				    
    xmlSecKeyDataPtr data = NULL;
    xmlNodePtr cur;
    xmlSecBuffer modulus, exponent;
    xmlSecBufferPtr blob;
    BLOBHEADER * header;
    unsigned int blobBufferLen;
    RSAPUBKEY * pubkey;
    BYTE *i;
    unsigned int j;
    BYTE *exponentBuf;
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    int ret;

    xmlSecAssert2(id == xmlSecMSCryptoKeyDataRsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    NULL,		    
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA,
		    "key already has a value");
	ret = -1;
	goto done;
    }

    cur = xmlSecGetNextElementNode(node->children);
    /* first is Modulus node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  xmlSecNodeRSAModulus, xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeRSAModulus));
	ret = -1;
	goto done;
    }
    if(xmlSecMSCryptoNodeGetBigNumValue(cur, &modulus) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecMSCryptoNodeGetBigNumValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeRSAModulus));
	ret = -1;
	goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is Exponent node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeRSAExponent, xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeRSAExponent));
	ret = -1;
	goto done;
    }
    if(xmlSecMSCryptoNodeGetBigNumValue(cur, &exponent) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecMSCryptoNodeGetBigNumValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeRSAExponent));
	ret = -1;
	goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeRSAPrivateExponent, xmlSecNs))) {
        /* next is X node. It is REQUIRED for private key but
	 * MSCrypto does not support it. We just ignore it */ 
	cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "no nodes expected");
	ret = -1;
	goto done;
    }

    /* Now try to create the key */
    blobBufferLen = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + xmlSecBufferGetSize(&modulus);
    blob = xmlSecBufferCreate(blobBufferLen);
    xmlSecBufferSetSize(blob, blobBufferLen);

    /* Set the blob header */
    header = (BLOBHEADER *)xmlSecBufferGetData(blob);
    header->bType = PUBLICKEYBLOB;
    header->bVersion = 0x02;
    header->reserved = 0;
    header->aiKeyAlg = CALG_RSA_KEYX | CALG_RSA_SIGN;

    /* Set the public key header */
    pubkey = (RSAPUBKEY *) (xmlSecBufferGetData(blob) + sizeof(BLOBHEADER));

    pubkey->magic = 0x31415352;	/* == RSA1 */
    pubkey->bitlen = xmlSecBufferGetSize(&modulus) * 8;	/* Number of bits in prime modulus */
    pubkey->pubexp = 0;
    i = ((BYTE *) &(pubkey->pubexp));
    exponentBuf = xmlSecBufferGetData(&exponent);
    for (j = 0; j < xmlSecBufferGetSize(&exponent); ++j) {
	*i++ = exponentBuf[j];
    }

    /* copy in the modulus */
    i = (BYTE *) (pubkey);
    i += sizeof(RSAPUBKEY);

    memcpy(i, xmlSecBufferGetData(&modulus), xmlSecBufferGetSize(&modulus));

    /* Now that we have the blob, import */
    if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) {
	if (NTE_BAD_KEYSET == GetLastError()) {
	    if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
		xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "CryptAcquireContext",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "Error no: %d", GetLastError());
		ret = -1;
		goto done;
	    }
	} else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "CryptAcquireContext",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	ret = -1;
	goto done;
	}
    }
    if (!CryptImportKey(hProv, xmlSecBufferGetData(blob), xmlSecBufferGetSize(blob), 0, 0, &hKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "CryptImportKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	ret = -1;
	goto done;

    }

    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecKeyDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	ret = -1;
	goto done;
    }

    ret = xmlSecMSCryptoKeyDataAdoptKey(data, hProv, TRUE, hKey, 0, xmlSecKeyDataTypePublic);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecMSCryptoKeyDataAdoptKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyDataDestroy(data);
	goto done;
    }
    hKey = 0;
     
    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecKeySetValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyDataDestroy(data);
	goto done;
    }
    data = NULL;

    ret = 0;

done:
    if (ret != 0) {
	if (hProv == 0) {
	    CryptReleaseContext(hProv, 0);
	}
	if (hKey != 0) {
            CryptDestroyKey(hKey);
	}
	if (data != 0) {
            xmlSecKeyDataDestroy(data);
	}
    }
    return(ret);
}

static int 
xmlSecMSCryptoKeyDataRsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    DWORD dwBlobLen;
    BYTE *blobBuffer, *i, *exponentBuffer;
    xmlSecBufferPtr blob, modulus, exponent;
    RSAPUBKEY *pk;
    DWORD keyLen;
    xmlNodePtr cur;
    int ret;
    unsigned int exponentLen;
    
    xmlSecAssert2(id == xmlSecMSCryptoKeyDataRsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecMSCryptoKeyDataRsaId), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    ctx = xmlSecMSCryptoKeyDataGetCtx(xmlSecKeyGetValue(key));
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hKey != 0, -1);

    if (!CryptExportKey(ctx->hKey, 0, PUBLICKEYBLOB, 0, NULL, &dwBlobLen)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "CryptExportKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    blob = xmlSecBufferCreate(dwBlobLen);
    xmlSecBufferSetSize(blob, dwBlobLen);
    blobBuffer = xmlSecBufferGetData(blob);
    if (!CryptExportKey(ctx->hKey, 0, PUBLICKEYBLOB, 0, blobBuffer, &dwBlobLen)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "CryptExportKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if (dwBlobLen < 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "CryptExportKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "Blob length < 1");
	return(-1);
    }

    pk = (RSAPUBKEY *)(blobBuffer + sizeof(BLOBHEADER));
    keyLen = pk->bitlen / 8;
    /* Copy the key */
    i = (BYTE *)pk;
    i += sizeof(RSAPUBKEY);
    modulus = xmlSecBufferCreate(keyLen);
    xmlSecBufferSetData(modulus, i, keyLen);

    exponent = xmlSecBufferCreate(4);
    xmlSecBufferSetData(exponent, (BYTE *)(&(pk->pubexp)), 4);

    /* Remove leading zero's (from least significant end) */
    exponentBuffer = xmlSecBufferGetData(exponent);
    exponentLen = 3;
    while (exponentLen > 0 && exponentBuffer[exponentLen] == 0) {
	exponentLen--;
    }
    exponentLen++;
    xmlSecBufferSetSize(exponent, exponentLen);

    /* first is Modulus node */
    cur = xmlSecAddChild(node, xmlSecNodeRSAModulus, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeRSAModulus));
	return(-1);	
    }
    ret = xmlSecMSCryptoNodeSetBigNumValue(cur, modulus, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecNssNodeSetBigNumValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeRSAModulus));
	return(-1);
    }    

    /* next is Exponent node. */
    cur = xmlSecAddChild(node, xmlSecNodeRSAExponent, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeRSAExponent));
	return(-1);	
    }
    ret = xmlSecMSCryptoNodeSetBigNumValue(cur, exponent, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecNssNodeSetBigNumValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeRSAExponent));
    return(-1);	
}

    /* next is PrivateExponent node: not supported in MSCrypto */

    return(0);
}

static int 
xmlSecMSCryptoKeyDataRsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, 
				xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    HCRYPTPROV hProv;
    DWORD dwKeySpec;
    HCRYPTKEY hKey;
    DWORD dwSize;
    int ret = -1;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataRsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);

    if (!CryptAcquireContext(&hProv, XMLSEC_CONTAINER_NAME, MS_STRONG_PROV, PROV_RSA_FULL, 0)) {
	if (NTE_BAD_KEYSET == GetLastError()) {
	    if(!CryptAcquireContext(&hProv, XMLSEC_CONTAINER_NAME, MS_STRONG_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "CryptAcquireContext",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "error code=%d", GetLastError());
        
	return(-1);
    }
	} else {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			    "CryptAcquireContext",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "error code=%d", GetLastError());
                
	    return(-1);
	}
    }

    dwKeySpec = AT_KEYEXCHANGE | AT_SIGNATURE;

    dwSize = ((sizeBits << 16) | CRYPT_EXPORTABLE);

    if (!CryptGenKey(hProv, CALG_RSA_SIGN, dwSize, &hKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "CryptGenKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "error code=%d", GetLastError());
	goto done;
    }

    ret = xmlSecMSCryptoKeyDataAdoptKey(data, hProv, TRUE, hKey, dwKeySpec, 
	xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecMSCryptoKeyDataAdoptKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    ret = 0;

done:
    if (ret == 0) {
	return (0);
    }

    if (hProv != 0) {
	CryptReleaseContext(ctx->hProv, 0);
    }

    if (hKey != 0) {
	CryptDestroyKey(hKey);
    }

    return(-1);
}

static xmlSecKeyDataType 
xmlSecMSCryptoKeyDataRsaGetType(xmlSecKeyDataPtr data) {
    return(xmlSecMSCryptoKeyDataGetType(data));
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

#ifndef XMLSEC_NO_DSA    
/**************************************************************************
 *
 * <dsig:DSAKeyValue> processing
 *
 *
 * The DSAKeyValue Element (http://www.w3.org/TR/xmldsig-core/#sec-DSAKeyValue)
 *
 * DSA keys and the DSA signature algorithm are specified in [DSS]. 
 * DSA public key values can have the following fields:
 *      
 *   * P - a prime modulus meeting the [DSS] requirements 
 *   * Q - an integer in the range 2**159 < Q < 2**160 which is a prime 
 *         divisor of P-1 
 *   * G - an integer with certain properties with respect to P and Q 
 *   * Y - G**X mod P (where X is part of the private key and not made 
 *	   public) 
 *   * J - (P - 1) / Q 
 *   * seed - a DSA prime generation seed 
 *   * pgenCounter - a DSA prime generation counter
 *
 * Parameter J is available for inclusion solely for efficiency as it is 
 * calculatable from P and Q. Parameters seed and pgenCounter are used in the 
 * DSA prime number generation algorithm specified in [DSS]. As such, they are 
 * optional but must either both be present or both be absent. This prime 
 * generation algorithm is designed to provide assurance that a weak prime is 
 * not being used and it yields a P and Q value. Parameters P, Q, and G can be 
 * public and common to a group of users. They might be known from application 
 * context. As such, they are optional but P and Q must either both appear or 
 * both be absent. If all of P, Q, seed, and pgenCounter are present, 
 * implementations are not required to check if they are consistent and are 
 * free to use either P and Q or seed and pgenCounter. All parameters are 
 * encoded as base64 [MIME] values.
 *     
 * Arbitrary-length integers (e.g. "bignums" such as RSA moduli) are 
 * represented in XML as octet strings as defined by the ds:CryptoBinary type.
 *     
 * Schema Definition:
 *     
 * <element name="DSAKeyValue" type="ds:DSAKeyValueType"/> 
 * <complexType name="DSAKeyValueType"> 
 *   <sequence>
 *     <sequence minOccurs="0">
 *        <element name="P" type="ds:CryptoBinary"/> 
 *        <element name="Q" type="ds:CryptoBinary"/>
 *     </sequence>
 *     <element name="G" type="ds:CryptoBinary" minOccurs="0"/> 
 *     <element name="Y" type="ds:CryptoBinary"/> 
 *     <element name="J" type="ds:CryptoBinary" minOccurs="0"/>
 *     <sequence minOccurs="0">
 *       <element name="Seed" type="ds:CryptoBinary"/> 
 *       <element name="PgenCounter" type="ds:CryptoBinary"/> 
 *     </sequence>
 *   </sequence>
 * </complexType>
 *     
 * DTD Definition:
 *     
 *  <!ELEMENT DSAKeyValue ((P, Q)?, G?, Y, J?, (Seed, PgenCounter)?) > 
 *  <!ELEMENT P (#PCDATA) >
 *  <!ELEMENT Q (#PCDATA) >
 *  <!ELEMENT G (#PCDATA) >
 *  <!ELEMENT Y (#PCDATA) >
 *  <!ELEMENT J (#PCDATA) >
 *  <!ELEMENT Seed (#PCDATA) >
 *  <!ELEMENT PgenCounter (#PCDATA) >
 *
 * ============================================================================
 * 
 * To support reading/writing private keys an X element added (before Y).
 * todo: The current implementation does not support Seed and PgenCounter!
 * by this the P, Q and G are *required*!
 *
 *************************************************************************/
static int		xmlSecMSCryptoKeyDataDsaInitialize(xmlSecKeyDataPtr data);
static int		xmlSecMSCryptoKeyDataDsaDuplicate(xmlSecKeyDataPtr dst,
							 xmlSecKeyDataPtr src);
static void		xmlSecMSCryptoKeyDataDsaFinalize(xmlSecKeyDataPtr data);
static int		xmlSecMSCryptoKeyDataDsaXmlRead	(xmlSecKeyDataId id,
							 xmlSecKeyPtr key,
							 xmlNodePtr node,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecMSCryptoKeyDataDsaXmlWrite(xmlSecKeyDataId id,
							 xmlSecKeyPtr key,
							 xmlNodePtr node,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecMSCryptoKeyDataDsaGenerate(xmlSecKeyDataPtr data,
							 xmlSecSize sizeBits,
							 xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecMSCryptoKeyDataDsaGetType(xmlSecKeyDataPtr data);
static xmlSecSize	 xmlSecMSCryptoKeyDataDsaGetSize(xmlSecKeyDataPtr data);
static void		 xmlSecMSCryptoKeyDataDsaDebugDump(xmlSecKeyDataPtr data,
							 FILE* output);
static void		xmlSecMSCryptoKeyDataDsaDebugXmlDump(xmlSecKeyDataPtr data,
							 FILE* output);

static xmlSecKeyDataKlass xmlSecMSCryptoKeyDataDsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCryptoKeyDataSize,

    /* data */
    xmlSecNameDSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
					/* xmlSecKeyDataUsage usage; */
    xmlSecHrefDSAKeyValue,		/* const xmlChar* href; */
    xmlSecNodeDSAKeyValue,		/* const xmlChar* dataNodeName; */
    xmlSecDSigNs,			/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecMSCryptoKeyDataDsaInitialize,	/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCryptoKeyDataDsaDuplicate,	/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCryptoKeyDataDsaFinalize,	/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecMSCryptoKeyDataDsaGenerate,	/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecMSCryptoKeyDataDsaGetType, 	/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecMSCryptoKeyDataDsaGetSize,	/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,				/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    xmlSecMSCryptoKeyDataDsaXmlRead,	/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecMSCryptoKeyDataDsaXmlWrite,	/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,				/* xmlSecKeyDataBinReadMethod binRead; */
    NULL,				/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCryptoKeyDataDsaDebugDump,	/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCryptoKeyDataDsaDebugXmlDump,/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,				/* void* reserved0; */
    NULL,				/* void* reserved1; */
};

/**
 * xmlSecMSCryptoKeyDataDsaGetKlass:
 * 
 * The DSA key data klass.
 *
 * Returns pointer to DSA key data klass.
 */
xmlSecKeyDataId 
xmlSecMSCryptoKeyDataDsaGetKlass(void) {
    return(&xmlSecMSCryptoKeyDataDsaKlass);
}


static int
xmlSecMSCryptoKeyDataDsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    
    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), xmlSecKeyDataTypeUnknown);

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataDsaId), -1);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCryptoKeyDataCtx));

    ctx->providerName = MS_DEF_DSS_PROV;
    ctx->providerType = PROV_DSS;
    
    return(0);
}

static int
xmlSecMSCryptoKeyDataDsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCryptoKeyDataDsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCryptoKeyDataDsaId), -1);

    return(xmlSecMSCryptoKeyDataDuplicate(dst, src));
}

static void
xmlSecMSCryptoKeyDataDsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataDsaId));
    
    xmlSecMSCryptoKeyDataFinalize(data);
}

static int
xmlSecMSCryptoKeyDataDsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
			   xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data = NULL;
    xmlNodePtr cur;
    xmlSecBuffer p, q, g, y;
    xmlSecBufferPtr keyBlob;
    BYTE *keyBlobBuf, *i;
    unsigned int blobBufferLen, j;
    BLOBHEADER *header;
    DSSPUBKEY *pubkey;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    int ret;

    xmlSecAssert2(id == xmlSecMSCryptoKeyDataDsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA,
		    XMLSEC_ERRORS_NO_MESSAGE);
	ret = -1;
	goto done;
    }

    cur = xmlSecGetNextElementNode(node->children);

    /* first is P node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  xmlSecNodeDSAP, xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAP));
	ret = -1;
	goto done;
    }
    if(xmlSecMSCryptoNodeGetBigNumValue(cur, &p) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecMSCryptoNodeGetBigNumValue",		    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAP));
	ret = -1;
	goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is Q node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAQ, xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAQ));
	ret = -1;
	goto done;
    }
    if(xmlSecMSCryptoNodeGetBigNumValue(cur, &q) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecMSCryptoNodeGetBigNumValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAQ));
	ret = -1;
	goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is G node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAG, xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAG));
	ret = -1;
	goto done;
    }
    if(xmlSecMSCryptoNodeGetBigNumValue(cur, &g) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecMSCryptoNodeGetBigNumValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAG));
	ret = -1;
	goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAX, xmlSecNs))) {
        /* next is X node. It is REQUIRED for private key but
	 * MSCrypto does not support it, we just ignore it */

	cur = xmlSecGetNextElementNode(cur->next);  
    }

    /* next is Y node. */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAY, xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAY));
	ret = -1;
	goto done;
    }
    if(xmlSecMSCryptoNodeGetBigNumValue(cur, &y) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecMSCryptoNodeGetBigNumValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAY));
	ret = -1;
	goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);
    
    /* todo: add support for seed */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSASeed, xmlSecDSigNs))) {
	cur = xmlSecGetNextElementNode(cur->next);  
    }

    /* todo: add support for pgencounter */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAPgenCounter, xmlSecDSigNs))) {
	cur = xmlSecGetNextElementNode(cur->next);  
    }

    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	ret = -1;
	goto done;
    }

    
    blobBufferLen = sizeof(BLOBHEADER) + sizeof(DSSPUBKEY) + (3 * xmlSecBufferGetSize(&p)) + 0x14 + 0x18 /*sizeof(DSSSEED)*/;
    keyBlob = xmlSecBufferCreate(blobBufferLen);
    xmlSecBufferSetSize(keyBlob, blobBufferLen);

    /* Set blob header */
    header = (BLOBHEADER *)xmlSecBufferGetData(keyBlob);
    header->bType = PUBLICKEYBLOB;
    header->bVersion = 0x02;
    header->reserved = 0;
    header->aiKeyAlg = CALG_DSS_SIGN;

    /* Set the public key header */
    pubkey = (DSSPUBKEY *) (xmlSecBufferGetData(keyBlob) + sizeof(BLOBHEADER));
    pubkey->magic = 0x31535344;	/* == DSS1 */
    pubkey->bitlen = xmlSecBufferGetSize(&p) * 8; /* Number of bits in prime modulus */

    /* copy the keys */
    i = (BYTE *)(pubkey);
    i += sizeof(DSSPUBKEY);

    memcpy(i, xmlSecBufferGetData(&p), xmlSecBufferGetSize(&p));
    i+= xmlSecBufferGetSize(&p);
    memcpy(i, xmlSecBufferGetData(&q), xmlSecBufferGetSize(&q));
    i+= xmlSecBufferGetSize(&q);
    /* Pad with zeros */
    for (j = xmlSecBufferGetSize(&q); j < 20 ; ++j) {
	*i++ = 0;
    }
    /* set generator */
    memcpy(i, xmlSecBufferGetData(&g), xmlSecBufferGetSize(&g));
    i+= xmlSecBufferGetSize(&g);
    /* Pad */
    for (j = xmlSecBufferGetSize(&g); j < xmlSecBufferGetSize(&p) ; ++j) {
	*i++ = 0;
    }
    /* Public key */
    memcpy(i, xmlSecBufferGetData(&y), xmlSecBufferGetSize(&y));
    i+= xmlSecBufferGetSize(&y);
    /* Pad */
    for (j = xmlSecBufferGetSize(&y); j < xmlSecBufferGetSize(&p) ; ++j)
	*i++ = 0;

    /* Set seed to 0 */
    for (j = 0; j < 0x18; ++j) {
	*i++ = 0xFF;	/* SEED Counter set to 0xFFFFFFFF will cause seed to be ignored */
    }


    if (!CryptAcquireContext(&hProv, NULL, MS_DEF_DSS_PROV, PROV_DSS, 0)) {
	if (NTE_BAD_KEYSET == GetLastError()) {
	    if (!CryptAcquireContext(&hProv, NULL, MS_DEF_DSS_PROV, PROV_DSS, CRYPT_NEWKEYSET)) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			    "CryptAcquireContext",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "Error no: %d", GetLastError());
		ret = -1;
		goto done;
	    }
	} else {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"CryptAcquireContext",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"Error no: %d", GetLastError());
	    ret = -1;
	    goto done;
	}
    }

    /* import the key blob */
    if (!CryptImportKey(hProv, xmlSecBufferGetData(keyBlob), xmlSecBufferGetSize(keyBlob), 0, 0, &hKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "CryptImportKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	ret = -1;
	goto done;
    }

    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecKeyDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	ret = -1;
	goto done;
    }

    ret = xmlSecMSCryptoKeyDataAdoptKey(data, hProv, TRUE, hKey, 0, xmlSecKeyDataTypePublic);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecMSCryptoKeyDataAdoptKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecKeySetValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }
    data = NULL;

    ret = 0;

done:
    if (ret != 0) {
	if (hKey != 0) {
	    CryptDestroyKey(hKey);
	}
	if (hProv != 0) {
	    CryptReleaseContext(hProv, 0);
	}
	if (data != NULL) {
	    xmlSecKeyDataDestroy(data);
	}
    }

    xmlSecBufferFinalize(keyBlob);
    xmlSecBufferFinalize(&p);
    xmlSecBufferFinalize(&q);
    xmlSecBufferFinalize(&g);
    xmlSecBufferFinalize(&y);

    return(ret);
}

static int 
xmlSecMSCryptoKeyDataDsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    DWORD dwBlobLen, keyLen;
    BYTE *blobBuffer, *i;
    xmlSecBufferPtr blob, p, q, g, y;
    DSSPUBKEY *pk;
    xmlNodePtr cur;
    int ret, len;
    
    xmlSecAssert2(id == xmlSecMSCryptoKeyDataDsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecMSCryptoKeyDataDsaId), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    ctx = xmlSecMSCryptoKeyDataGetCtx(xmlSecKeyGetValue(key));
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hKey != 0, -1);
    
    if (!CryptExportKey(ctx->hKey, 0, PUBLICKEYBLOB, 0, NULL, &dwBlobLen)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "CryptExportKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    blob = xmlSecBufferCreate(dwBlobLen);
    xmlSecBufferSetSize(blob, dwBlobLen);
    blobBuffer = xmlSecBufferGetData(blob);
    if (!CryptExportKey(ctx->hKey, 0, PUBLICKEYBLOB, 0, blobBuffer, &dwBlobLen)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "CryptExportKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if (dwBlobLen < 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "CryptExportKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "Blob length < 1");
	return(-1);
    }

    /* Now first get all the needed buffers */
    /* TODO: Adds loads of xmlSecBuffer error catching and handling */
    pk = (DSSPUBKEY *)(blobBuffer + sizeof(BLOBHEADER));
    keyLen = pk->bitlen / 8;
	
    i = (BYTE *)(pk);
    i += sizeof(DSSPUBKEY);

    p = xmlSecBufferCreate(keyLen);
    xmlSecBufferSetData(p, i, keyLen);
    i+=keyLen;

    len = 20;
    while (i[len - 1] == 0 && len > 0) {
	len--;
    }
    q = xmlSecBufferCreate(len);
    xmlSecBufferSetData(q, i, len);
    i+=20;

    len = keyLen;
    while (i[len - 1] == 0 && len > 0) {
	len--;
    }
    g = xmlSecBufferCreate(len);
    xmlSecBufferSetData(g, i, len);
    i+=keyLen;

    len = keyLen;
    while (i[len] == 0 && len > 0) {
	len--;
    }
    y = xmlSecBufferCreate(len);
    xmlSecBufferSetData(y, i, len);

    /* first is P node */
    cur = xmlSecAddChild(node, xmlSecNodeDSAP, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAP));
	return(-1);	
    }
    ret = xmlSecMSCryptoNodeSetBigNumValue(cur, p, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecMSCryptoNodeSetBigNumValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAP));
	return(-1);
    }    

    /* next is Q node. */
    cur = xmlSecAddChild(node, xmlSecNodeDSAQ, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAQ));
	return(-1);	
    }
    ret = xmlSecMSCryptoNodeSetBigNumValue(cur, q, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecMSCryptoNodeSetBigNumValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAQ));
	return(-1);
    }

    /* next is G node. */
    cur = xmlSecAddChild(node, xmlSecNodeDSAG, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAG));
	return(-1);	
    }
    ret = xmlSecMSCryptoNodeSetBigNumValue(cur, g, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecMSCryptoNodeSetBigNumValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAG));
    return(-1);
}

    /* next is X node: not supported in MSCrypto */

    /* next is Y node. */
    cur = xmlSecAddChild(node, xmlSecNodeDSAY, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAY));
	return(-1);	
    }
    ret = xmlSecMSCryptoNodeSetBigNumValue(cur, y, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecNssNodeSetBigNumValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAY));
	return(-1);
    }

    return(0);
}

static int
xmlSecMSCryptoKeyDataDsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    HCRYPTPROV hProv; 
    DWORD dwKeySpec;
    HCRYPTKEY hKey;
    DWORD dwSize;
    int ret = -1;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataDsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);

    if(!CryptAcquireContext(&hProv, XMLSEC_CONTAINER_NAME, ctx->providerName, ctx->providerType, 0)) {
	if (NTE_BAD_KEYSET == GetLastError()) {
	    if(!CryptAcquireContext(&hProv, XMLSEC_CONTAINER_NAME, ctx->providerName, ctx->providerType, CRYPT_NEWKEYSET)) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			    "CryptAcquireContext",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "error code=%d", GetLastError());
		return(-1);
	    }
	} else {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			"CryptAcquireContext",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"error code=%d", GetLastError());
	    return(-1);
	}
    }

    dwKeySpec = AT_SIGNATURE;
    dwSize = ((sizeBits << 16) | CRYPT_EXPORTABLE);

    if (!CryptGenKey(hProv, CALG_DSS_SIGN, dwSize, &hKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "CryptGenKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "error code=%d", GetLastError());
	goto done;
    }

    ret = xmlSecMSCryptoKeyDataAdoptKey(data, hProv, TRUE, hKey, dwKeySpec, 
	xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecMSCryptoKeyDataAdoptKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    ret = 0;

done:
    if (ret == 0) {
	return (0);
    }

    if (hProv != 0) {
	CryptReleaseContext(ctx->hProv, 0);
    }

    if (hKey != 0) {
	CryptDestroyKey(hKey);
    }

    return(-1);
}

static xmlSecKeyDataType
xmlSecMSCryptoKeyDataDsaGetType(xmlSecKeyDataPtr data) {
    return(xmlSecMSCryptoKeyDataGetType(data));
}

static xmlSecSize 
xmlSecMSCryptoKeyDataDsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataDsaId), 0);

    return xmlSecMSCryptoKeyDataGetSize(data);
}

static void 
xmlSecMSCryptoKeyDataDsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataDsaId));
    xmlSecAssert(output != NULL);
    
    fprintf(output, "=== dsa key: size = %d\n", 
	    xmlSecMSCryptoKeyDataDsaGetSize(data));
}

static void
xmlSecMSCryptoKeyDataDsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataDsaId));
    xmlSecAssert(output != NULL);
        
    fprintf(output, "<DSAKeyValue size=\"%d\" />\n", 
	    xmlSecMSCryptoKeyDataDsaGetSize(data));
}

#endif /* XMLSEC_NO_DSA */


