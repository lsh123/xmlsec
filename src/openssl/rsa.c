/** 
 *
 * XMLSec library
 * 
 * RSA Algorithm support
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_RSA

#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/membuf.h>
#include <xmlsec/strings.h>
#include <xmlsec/debug.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/openssl/bn.h>

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
 * To support reading/writing private keys an PrivateExponent element is added
 * to the end
 *
 *************************************************************************/

static int		xmlSecOpenSSLKeyDataRsaInitialize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataRsaDuplicate	(xmlSecKeyDataPtr dst,
								 xmlSecKeyDataPtr src);
static void		xmlSecOpenSSLKeyDataRsaFinalize		(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataRsaXmlRead		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataRsaXmlWrite		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataRsaGenerate		(xmlSecKeyDataPtr data,
							    	 size_t sizeBits);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataRsaGetType		(xmlSecKeyDataPtr data);
static size_t		xmlSecOpenSSLKeyDataRsaGetSize		(xmlSecKeyDataPtr data);
static void		xmlSecOpenSSLKeyDataRsaDebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecOpenSSLKeyDataRsaDebugXmlDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataRsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),

    /* data */
    xmlSecNameRSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefRSAKeyValue,			/* const xmlChar* href; */
    xmlSecNodeRSAKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecDSigNs,				/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecOpenSSLKeyDataRsaInitialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataRsaDuplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataRsaFinalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecOpenSSLKeyDataRsaGenerate,		/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecOpenSSLKeyDataRsaGetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataRsaGetSize,		/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    xmlSecOpenSSLKeyDataRsaXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataRsaXmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,					/* xmlSecKeyDataBinReadMethod binRead; */
    NULL,					/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataRsaDebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataRsaDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

xmlSecKeyDataId 
xmlSecOpenSSLKeyDataRsaGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataRsaKlass);
}

int
xmlSecOpenSSLKeyDataRsaAdoptRsa(xmlSecKeyDataPtr data, RSA* rsa) {
    EVP_PKEY* pKey = NULL;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);
    
    /* construct new EVP_PKEY */
    if(rsa != NULL) {
	pKey = EVP_PKEY_new();
	if(pKey == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			"EVP_PKEY_new",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	
	ret = EVP_PKEY_assign_RSA(pKey, rsa);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			"EVP_PKEY_assign_RSA",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}	
    }
    
    ret = xmlSecOpenSSLKeyDataRsaAdoptEvp(data, pKey);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecOpenSSLKeyDataRsaAdoptEvp",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	if(pKey != NULL) {
	    EVP_PKEY_free(pKey);
	}
	return(-1);
    }
    return(0);    
}

RSA* 
xmlSecOpenSSLKeyDataRsaGetRsa(xmlSecKeyDataPtr data) {
    EVP_PKEY* pKey;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), NULL);
    
    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(data);
    xmlSecAssert2((pKey == NULL) || (pKey->type == EVP_PKEY_RSA), NULL);
    
    return((pKey != NULL) ? pKey->pkey.rsa : (RSA*)NULL);
}

int 
xmlSecOpenSSLKeyDataRsaAdoptEvp(xmlSecKeyDataPtr data, EVP_PKEY* pKey) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2((pKey == NULL) || (pKey->type == EVP_PKEY_RSA), -1);
    
    /* finalize the old one */
    if(data->reserved0 != NULL) {
	EVP_PKEY_free((EVP_PKEY*)(data->reserved0));
	data->reserved0 = NULL;
    }    
    
    data->reserved0 = pKey;
    return(0);
}

EVP_PKEY* 
xmlSecOpenSSLKeyDataRsaGetEvp(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), NULL);

    return((EVP_PKEY*)(data->reserved0));
}

static int
xmlSecOpenSSLKeyDataRsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);

    return(0);
}

static int
xmlSecOpenSSLKeyDataRsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    EVP_PKEY* pKeySrc;
    EVP_PKEY* pKeyDst = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataRsaId), -1);

    pKeySrc = xmlSecOpenSSLKeyDataRsaGetEvp(src);
    if(pKeySrc != NULL) {
	pKeyDst = xmlSecOpenSSLEvpKeyDup(pKeySrc);
	if(pKeyDst == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"xmlSecOpenSSLEvpKeyDup",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}	
    } 
    
    ret = xmlSecOpenSSLKeyDataRsaAdoptEvp(dst, pKeyDst);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
		    "xmlSecOpenSSLKeyDataRsaAdoptEvp",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	EVP_PKEY_free(pKeyDst);
	return(-1);
    }

    return(0);
}

static void
xmlSecOpenSSLKeyDataRsaFinalize(xmlSecKeyDataPtr data) {
    int ret;
    
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId));
    
    /* finalize buffer */
    ret = xmlSecOpenSSLKeyDataRsaAdoptEvp(data, NULL);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecOpenSSLKeyDataRsaAdoptEvp",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
    }
}

static int
xmlSecOpenSSLKeyDataRsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    xmlNodePtr cur;
    RSA *rsa;
    int ret;

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataRsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    NULL,		    
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA,
		    "key already has a value");
	return(-1);	
    }

    rsa = RSA_new();
    if(rsa == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "RSA_new",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    cur = xmlSecGetNextElementNode(node->children);
    
    /* first is Modulus node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  xmlSecNodeRSAModulus, xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecNodeGetName(cur),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeRSAModulus));
	RSA_free(rsa);	
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(rsa->n)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeGetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeRSAModulus));
	RSA_free(rsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is Exponent node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeRSAExponent, xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecNodeGetName(cur),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeRSAExponent));
	RSA_free(rsa);
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(rsa->e)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeGetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeRSAExponent));
	RSA_free(rsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeRSAPrivateExponent, xmlSecNs))) {
        /* next is X node. It is REQUIRED for private key but
	 * we are not sure exactly what do we read */
	if(xmlSecOpenSSLNodeGetBNValue(cur, &(rsa->d)) == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecOpenSSLNodeGetBNValue",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"%s", xmlSecErrorsSafeString(xmlSecNodeRSAPrivateExponent));
	    RSA_free(rsa);
	    return(-1);
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecNodeGetName(cur),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "no nodes expected");
	RSA_free(rsa);
	return(-1);
    }

    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecKeyDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	RSA_free(rsa);
	return(-1);
    }

    ret = xmlSecOpenSSLKeyDataRsaAdoptRsa(data, rsa);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLKeyDataRsaAdoptRsa",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyDataDestroy(data);
	RSA_free(rsa);
	return(-1);
    }

    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecKeySetValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyDataDestroy(data);
	return(-1);	
    }

    return(0);
}

static int 
xmlSecOpenSSLKeyDataRsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
			    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlNodePtr cur;
    RSA* rsa;
    int ret;
    
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataRsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    rsa = xmlSecOpenSSLKeyDataRsaGetRsa(xmlSecKeyGetValue(key));
    xmlSecAssert2(rsa != NULL, -1);
    
    if(((xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate) & keyInfoCtx->keyType) == 0) {
	/* we can have only private key or public key */
	return(0);
    }    

    /* first is Modulus node */
    cur = xmlSecAddChild(node, xmlSecNodeRSAModulus, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeRSAModulus));
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, rsa->n, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeSetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeRSAModulus));
	return(-1);
    }    

    /* next is Exponent node. */
    cur = xmlSecAddChild(node, xmlSecNodeRSAExponent, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeRSAExponent));
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, rsa->e, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeSetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeRSAExponent));
	return(-1);
    }

    /* next is PrivateExponent node: write it ONLY for private keys and ONLY if it is requested */
    if(((keyInfoCtx->keyType & xmlSecKeyDataTypePrivate) != 0) && (rsa->d != NULL)) {
	cur = xmlSecAddChild(node, xmlSecNodeRSAPrivateExponent, xmlSecNs);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecAddChild",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
		        "%s", xmlSecErrorsSafeString(xmlSecNodeRSAPrivateExponent));
	    return(-1);	
	}
	ret = xmlSecOpenSSLNodeSetBNValue(cur, rsa->d, 1);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecOpenSSLNodeSetBNValue",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
		        "%s", xmlSecErrorsSafeString(xmlSecNodeRSAPrivateExponent));
	    return(-1);
	}
    }
    
    return(0);
}

static int
xmlSecOpenSSLKeyDataRsaGenerate(xmlSecKeyDataPtr data, size_t sizeBits) {
    RSA* rsa;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    rsa = RSA_generate_key(sizeBits, 3, NULL, NULL); 
    if(rsa == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "RSA_generate_key",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "%d", sizeBits);
	return(-1);    
    }

    ret = xmlSecOpenSSLKeyDataRsaAdoptRsa(data, rsa);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecOpenSSLKeyDataRsaAdoptRsa",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	RSA_free(rsa);
	return(-1);
    }

    return(0);
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataRsaGetType(xmlSecKeyDataPtr data) {
    RSA* rsa;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), xmlSecKeyDataTypeUnknown);
    
    rsa = xmlSecOpenSSLKeyDataRsaGetRsa(data);
    if((rsa != NULL) && (rsa->n != NULL) && (rsa->e != NULL)) {
	if(rsa->d != NULL) {
	    return(xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
	} else {
	    return(xmlSecKeyDataTypePublic);
	}
    }

    return(xmlSecKeyDataTypeUnknown);
}

static size_t 
xmlSecOpenSSLKeyDataRsaGetSize(xmlSecKeyDataPtr data) {
    RSA* rsa;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), 0);

    rsa = xmlSecOpenSSLKeyDataRsaGetRsa(data);
    if((rsa != NULL) && (rsa->n != NULL)) {
	return(BN_num_bits(rsa->n));
    }    
    return(0);
}

static void 
xmlSecOpenSSLKeyDataRsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId));
    xmlSecAssert(output != NULL);
    
    fprintf(output, "=== rsa key: size = %d\n", 
	    xmlSecOpenSSLKeyDataRsaGetSize(data));
}

static void
xmlSecOpenSSLKeyDataRsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId));
    xmlSecAssert(output != NULL);
        
    fprintf(output, "<RSAKeyValue size=\"%d\" />\n", 
	    xmlSecOpenSSLKeyDataRsaGetSize(data));
}

/****************************************************************************
 *
 * RSA-SHA1 signature transform
 *
 ***************************************************************************/
static int 	xmlSecOpenSSLRsaSha1Initialize			(xmlSecTransformPtr transform);
static void 	xmlSecOpenSSLRsaSha1Finalize			(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLRsaSha1SetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecOpenSSLRsaSha1SetKey			(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecOpenSSLRsaSha1Verify			(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
								 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecOpenSSLRsaSha1Execute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);


static xmlSecTransformKlass xmlSecOpenSSLRsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLEvpSignatureSize,		/* size_t objSize */

    xmlSecNameRsaSha1,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    xmlSecHrefRsaSha1, 				/* xmlChar *href; */
    
    xmlSecOpenSSLRsaSha1Initialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLRsaSha1Finalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadNodeMethod read; */
    xmlSecOpenSSLRsaSha1SetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLRsaSha1SetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLRsaSha1Verify,			/* xmlSecTransformVerifyMethod verify; */
    xmlSecOpenSSLRsaSha1Execute,		/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

xmlSecTransformId 
xmlSecOpenSSLTransformRsaSha1GetKlass(void) {
    return(&xmlSecOpenSSLRsaSha1Klass);
}


static int 
xmlSecOpenSSLRsaSha1Initialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha1Id), -1);
    
    return(xmlSecOpenSSLEvpSignatureInitialize(transform, EVP_sha1()));
}

static void 
xmlSecOpenSSLRsaSha1Finalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha1Id));

    xmlSecOpenSSLEvpSignatureFinalize(transform);
}

static int  
xmlSecOpenSSLRsaSha1SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha1Id), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	     = xmlSecOpenSSLKeyDataRsaId;
    if(transform->encode) {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePrivate;
	keyInfoCtx->keyUsage = xmlSecKeyUsageSign;
    } else {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePublic;
	keyInfoCtx->keyUsage = xmlSecKeyUsageVerify;
    }
    return(0);
}

static int 
xmlSecOpenSSLRsaSha1SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    EVP_PKEY* pKey;
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha1Id), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataRsaId), -1);
    
    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(xmlSecKeyGetValue(key));
    if(pKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLKeyDataRsaGetEvp",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    ret = xmlSecOpenSSLEvpSignatureSetKey(transform, pKey);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLEvpSignatureSetKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    return(0);
}

static int 
xmlSecOpenSSLRsaSha1Verify(xmlSecTransformPtr transform, const unsigned char* data,
		    size_t dataSize, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha1Id), -1);

    return(xmlSecOpenSSLEvpSignatureVerify(transform, data, dataSize, transformCtx));
}

static int 
xmlSecOpenSSLRsaSha1Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha1Id), -1);
    
    return(xmlSecOpenSSLEvpSignatureExecute(transform, last, transformCtx));
}

/*********************************************************************
 *
 * RSA PKCS1 key transport transform
 *
 * reserved0->key (EVP_PKEY*)
 *
 ********************************************************************/
static int 	xmlSecOpenSSLRsaPkcs1Initialize			(xmlSecTransformPtr transform);
static void 	xmlSecOpenSSLRsaPkcs1Finalize			(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLRsaPkcs1SetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecOpenSSLRsaPkcs1SetKey			(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecOpenSSLRsaPkcs1Execute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecOpenSSLRsaPkcs1Process			(xmlSecTransformPtr transform, 
								 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecOpenSSLRsaPkcs1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    sizeof(xmlSecTransform),			/* size_t objSize */

    xmlSecNameRsaPkcs1,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefRsaPkcs1, 			/* const xmlChar href; */

    xmlSecOpenSSLRsaPkcs1Initialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLRsaPkcs1Finalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLRsaPkcs1SetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLRsaPkcs1SetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLRsaPkcs1Execute,		/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

#define xmlSecOpenSSLRsaPkcs1GetKey(transform) \
    ((EVP_PKEY*)((transform)->reserved0))

xmlSecTransformId 
xmlSecOpenSSLTransformRsaPkcs1GetKlass(void) {
    return(&xmlSecOpenSSLRsaPkcs1Klass);
}

static int 
xmlSecOpenSSLRsaPkcs1Initialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2(xmlSecOpenSSLRsaPkcs1GetKey(transform) == NULL, -1);
    
    return(0);
}

static void 
xmlSecOpenSSLRsaPkcs1Finalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id));
    
    if(xmlSecOpenSSLRsaPkcs1GetKey(transform) != NULL) {
	EVP_PKEY_free(xmlSecOpenSSLRsaPkcs1GetKey(transform));
	transform->reserved0 = NULL;
    }
}

static int  
xmlSecOpenSSLRsaPkcs1SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecOpenSSLKeyDataRsaId;
    if(transform->encode) {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePublic;
	keyInfoCtx->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePrivate;
	keyInfoCtx->keyUsage = xmlSecKeyUsageDecrypt;
    }
    
    return(0);
}

static int  	
xmlSecOpenSSLRsaPkcs1SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    EVP_PKEY* pKey;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2(xmlSecOpenSSLRsaPkcs1GetKey(transform) == NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataRsaId), -1);

    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(xmlSecKeyGetValue(key));
    if(pKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLKeyDataRsaGetEvp",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    xmlSecAssert2(pKey->type == EVP_PKEY_RSA, -1);    
    xmlSecAssert2(pKey->pkey.rsa != NULL, -1);    
    
    transform->reserved0 = xmlSecOpenSSLEvpKeyDup(pKey);    
    if(transform->reserved0 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLEvpKeyDup",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);    
    }

    return(0);
}

static int 
xmlSecOpenSSLRsaPkcs1Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
	transform->status = xmlSecTransformStatusWorking;
    } else if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
	/* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
	ret = xmlSecOpenSSLRsaPkcs1Process(transform, transformCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecOpenSSLRsaPkcs1Process",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
	/* the only way we can get here is if there is no input */
	xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_STATUS,
		    "%d", transform->status);
	return(-1);
    }
    return(0);
}

static int  
xmlSecOpenSSLRsaPkcs1Process(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr in, out;
    size_t inSize, outSize;
    EVP_PKEY* pKey;
    size_t keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    pKey = xmlSecOpenSSLRsaPkcs1GetKey(transform);
    xmlSecAssert2(pKey != NULL, -1);
    xmlSecAssert2(pKey->type == EVP_PKEY_RSA, -1);    
    xmlSecAssert2(pKey->pkey.rsa != NULL, -1);    
    
    keySize = RSA_size(pKey->pkey.rsa);
    xmlSecAssert2(keySize > 0, -1);
    
    in = &(transform->inBuf);
    out = &(transform->outBuf);
	
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);    
    xmlSecAssert2(outSize == 0, -1);

    /* the encoded size is equal to the keys size so we could not
     * process more than that */
    if((transform->encode) && (inSize >= keySize)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "%d when expected less than %d", inSize, keySize);
	return(-1);
    } else if((!transform->encode) && (inSize != keySize)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "%d when expected %d", inSize, keySize);
	return(-1);
    }
	
    outSize = keySize; 
    ret = xmlSecBufferSetMaxSize(out, outSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferSetMaxSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%d", outSize);
	return(-1);
    }

    if(transform->encode) {
	ret = RSA_public_encrypt(inSize, xmlSecBufferGetData(in),
				xmlSecBufferGetData(out), 
				pKey->pkey.rsa, RSA_PKCS1_PADDING);
	if(ret <= 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_public_encrypt",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"%d", inSize);
	    return(-1);
	}
	outSize = ret;
    } else {
	ret = RSA_private_decrypt(inSize, xmlSecBufferGetData(in),
				xmlSecBufferGetData(out), 
				pKey->pkey.rsa, RSA_PKCS1_PADDING);
	if(ret <= 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_private_decrypt",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"%d", inSize);
	    return(-1);
	}
	outSize = ret;
    }

    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferSetSize",		    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%d", outSize);
	return(-1);
    }
	
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferRemoveHead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%d", inSize);
	return(-1);
    }
    
    return(0);
}

/*********************************************************************
 *
 * RSA OAEP key transport transform
 *
 * reserved0->key (EVP_PKEY*)
 *
 * OAEP Params (xmlSecBuffer) is located after xmlSecTransform structure
 *
 ********************************************************************/
#define xmlSecOpenSSLRsaOaepGetKey(transform) \
    ((EVP_PKEY*)((transform)->reserved0))
#define xmlSecOpenSSLRsaOaepGetParams(transform) \
    ((xmlSecBufferPtr)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecOpenSSLRsaOaepSize \
    (sizeof(xmlSecTransform) + sizeof(xmlSecBuffer))

static int 	xmlSecOpenSSLRsaOaepInitialize			(xmlSecTransformPtr transform);
static void 	xmlSecOpenSSLRsaOaepFinalize			(xmlSecTransformPtr transform);
static int 	xmlSecOpenSSLRsaOaepReadNode			(xmlSecTransformPtr transform, 
								 xmlNodePtr node);
static int  	xmlSecOpenSSLRsaOaepSetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecOpenSSLRsaOaepSetKey			(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecOpenSSLRsaOaepExecute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecOpenSSLRsaOaepProcess			(xmlSecTransformPtr transform, 
								 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecOpenSSLRsaOaepKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLRsaOaepSize,			/* size_t objSize */

    xmlSecNameRsaOaep,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefRsaOaep, 				/* const xmlChar href; */

    xmlSecOpenSSLRsaOaepInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLRsaOaepFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLRsaOaepReadNode,		/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLRsaOaepSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLRsaOaepSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLRsaOaepExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};


xmlSecTransformId 
xmlSecOpenSSLTransformRsaOaepGetKlass(void) {
    return(&xmlSecOpenSSLRsaOaepKlass);
}

static int 
xmlSecOpenSSLRsaOaepInitialize(xmlSecTransformPtr transform) {
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);

    ret = xmlSecBufferInitialize(xmlSecOpenSSLRsaOaepGetParams(transform), 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    transform->reserved0 = NULL;
    
    return(0);
}

static void 
xmlSecOpenSSLRsaOaepFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize));
    
    if(xmlSecOpenSSLRsaOaepGetKey(transform) != NULL) {
	EVP_PKEY_free(xmlSecOpenSSLRsaOaepGetKey(transform));
    }

    if(xmlSecOpenSSLRsaOaepGetParams(transform) != NULL) {
	xmlSecBufferFinalize(xmlSecOpenSSLRsaOaepGetParams(transform));
    }
    transform->reserved0 = NULL;
}

static int 	
xmlSecOpenSSLRsaOaepReadNode(xmlSecTransformPtr transform, xmlNodePtr node) {
    xmlSecBufferPtr params;
    xmlNodePtr cur;
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(node != NULL, -1);
    
    params = xmlSecOpenSSLRsaOaepGetParams(transform);
    xmlSecAssert2(params != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(params) == 0, -1);
    
    cur = xmlSecGetNextElementNode(node->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur,  xmlSecNodeRsaOAEPparams, xmlSecEncNs)) {
	ret = xmlSecBufferBase64NodeContentRead(params, cur);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferBase64NodeContentRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    if((cur != NULL) && xmlSecCheckNodeName(cur,  xmlSecNodeDigestMethod, xmlSecDSigNs)) {
	xmlChar* algorithm;

	/* Algorithm attribute is required */
	algorithm = xmlGetProp(cur, xmlSecAttrAlgorithm);
	if(algorithm == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			xmlSecNodeGetName(cur),
			XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE,
			"attr=%s", 
			xmlSecErrorsSafeString(xmlSecAttrAlgorithm));
	    return(-1);		
        }

	/* for now we support only sha1 */	
	if(strcmp(algorithm, xmlSecHrefSha1) != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			(char*)algorithm,
			XMLSEC_ERRORS_R_INVALID_TRANSFORM,
			"digest algorithm is not supported for rsa/oaep");
	    xmlFree(algorithm);
	    return(-1);		
	}
	xmlFree(algorithm);
	
	cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    xmlSecNodeGetName(cur),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "no nodes expected");
	return(-1);
    }
        
    return(0);
}

static int  
xmlSecOpenSSLRsaOaepSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecOpenSSLKeyDataRsaId;
    if(transform->encode) {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePublic;
	keyInfoCtx->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePrivate;
	keyInfoCtx->keyUsage = xmlSecKeyUsageDecrypt;
    }
    
    return(0);
}

static int  	
xmlSecOpenSSLRsaOaepSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    EVP_PKEY* pKey;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(xmlSecOpenSSLRsaOaepGetKey(transform) == NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataRsaId), -1);

    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(xmlSecKeyGetValue(key));
    if(pKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLKeyDataRsaGetEvp",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    xmlSecAssert2(pKey->type == EVP_PKEY_RSA, -1);    
    xmlSecAssert2(pKey->pkey.rsa != NULL, -1);    
    
    transform->reserved0 = xmlSecOpenSSLEvpKeyDup(pKey);    
    if(transform->reserved0 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLEvpKeyDup",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);    
    }

    return(0);
}

static int 
xmlSecOpenSSLRsaOaepExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
	transform->status = xmlSecTransformStatusWorking;
    } else if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
	/* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
	ret = xmlSecOpenSSLRsaOaepProcess(transform, transformCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecOpenSSLRsaOaepProcess",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
	/* the only way we can get here is if there is no input */
	xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_STATUS,
		    "%d", transform->status);
	return(-1);
    }
    return(0);
}

static int  
xmlSecOpenSSLRsaOaepProcess(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr params;
    size_t paramsSize;
    xmlSecBufferPtr in, out;
    size_t inSize, outSize;
    EVP_PKEY* pKey;
    size_t keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    params = xmlSecOpenSSLRsaOaepGetParams(transform);
    xmlSecAssert2(params != NULL, -1);

    pKey = xmlSecOpenSSLRsaOaepGetKey(transform);
    xmlSecAssert2(pKey != NULL, -1);
    xmlSecAssert2(pKey->type == EVP_PKEY_RSA, -1);    
    xmlSecAssert2(pKey->pkey.rsa != NULL, -1);    
    
    keySize = RSA_size(pKey->pkey.rsa);
    xmlSecAssert2(keySize > 0, -1);
    
    in = &(transform->inBuf);
    out = &(transform->outBuf);
	
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);    
    xmlSecAssert2(outSize == 0, -1);

    /* the encoded size is equal to the keys size so we could not
     * process more than that */
    if((transform->encode) && (inSize >= keySize)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "%d when expected less than %d", inSize, keySize);
	return(-1);
    } else if((!transform->encode) && (inSize != keySize)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "%d when expected %d", inSize, keySize);
	return(-1);
    }
	
    outSize = keySize; 
    ret = xmlSecBufferSetMaxSize(out, outSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferSetMaxSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%d", outSize);
	return(-1);
    }

    paramsSize = xmlSecBufferGetSize(params);
    if(transform->encode && (paramsSize == 0)) {
	/* encode w/o OAEPParams --> simple */
	ret = RSA_public_encrypt(inSize, xmlSecBufferGetData(in),
				xmlSecBufferGetData(out), 
				pKey->pkey.rsa, RSA_PKCS1_OAEP_PADDING);
	if(ret <= 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_public_encrypt(RSA_PKCS1_OAEP_PADDING)",			
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	outSize = ret;
    } else if(transform->encode && (paramsSize > 0)) {
	xmlSecAssert2(xmlSecBufferGetData(params) != NULL, -1);
	
	/* add space for padding */
	ret = xmlSecBufferSetMaxSize(in, keySize);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferSetMaxSize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"%d", keySize);
	    return(-1);
	}
	
	/* add padding */
	ret = RSA_padding_add_PKCS1_OAEP(xmlSecBufferGetData(in), keySize, 
					 xmlSecBufferGetData(in), inSize,
					 xmlSecBufferGetData(params), paramsSize);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_padding_add_PKCS1_OAEP",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}	
	inSize = keySize;

	/* encode with OAEPParams */
	ret = RSA_public_encrypt(inSize, xmlSecBufferGetData(in),
				xmlSecBufferGetData(out), 
				pKey->pkey.rsa, RSA_NO_PADDING);
	if(ret <= 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_public_encrypt(RSA_NO_PADDING)",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	outSize = ret;
    } else if((transform->encode == 0) && (paramsSize == 0)) {
	ret = RSA_private_decrypt(inSize, xmlSecBufferGetData(in),
				xmlSecBufferGetData(out), 
				pKey->pkey.rsa, RSA_PKCS1_OAEP_PADDING);
	if(ret <= 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_private_decrypt(RSA_PKCS1_OAEP_PADDING)",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	outSize = ret;
    } else if((transform->encode == 0) && (paramsSize != 0)) {
	BIGNUM bn;
	
	ret = RSA_private_decrypt(inSize, xmlSecBufferGetData(in),
				xmlSecBufferGetData(out), 
				pKey->pkey.rsa, RSA_NO_PADDING);
	if(ret <= 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_private_decrypt(RSA_NO_PADDING)",			
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	outSize = ret;
	
	/* 
    	 * the private decrypt w/o padding adds '0's at the begginning.
	 * it's not clear for me can I simply skip all '0's from the
	 * beggining so I have to do decode it back to BIGNUM and dump
	 * buffer again
	 */
	BN_init(&bn);
	if(BN_bin2bn(xmlSecBufferGetData(out), outSize, &bn) == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"BN_bin2bn",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"size=%d", outSize);
	    BN_clear_free(&bn);
	    return(-1);		    
	}
	
	ret = BN_bn2bin(&bn, xmlSecBufferGetData(out));
	if(ret <= 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"BN_bn2bin",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    BN_clear_free(&bn);
	    return(-1);		    
	}
	BN_clear_free(&bn);
	outSize = ret;

	ret = RSA_padding_check_PKCS1_OAEP(xmlSecBufferGetData(out), outSize,
					   xmlSecBufferGetData(out), outSize,
					   keySize,
					   xmlSecBufferGetData(params), paramsSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_padding_check_PKCS1_OAEP",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}	
	outSize = ret;	
    } else {
	xmlSecAssert2("we could not be here" == NULL, -1);
	return(-1);
    }

    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%d", outSize);
	return(-1);
    }
	
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferRemoveHead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%d", inSize);
	return(-1);
    }
    
    return(0);
}

#endif /* XMLSEC_NO_RSA */

