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
#include <xmlsec/buffered.h>
#include <xmlsec/base64.h>
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

static int		xmlSecOpenSSLKeyDataRsaValueInitialize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataRsaValueDuplicate	(xmlSecKeyDataPtr dst,
								 xmlSecKeyDataPtr src);
static void		xmlSecOpenSSLKeyDataRsaValueFinalize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataRsaValueXmlRead	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataRsaValueXmlWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataRsaValueGenerate	(xmlSecKeyDataPtr data,
								 size_t sizeBits);

static xmlSecKeyDataType	xmlSecOpenSSLKeyDataRsaValueGetType	(xmlSecKeyDataPtr data);
static size_t		xmlSecOpenSSLKeyDataRsaValueGetSize	(xmlSecKeyDataPtr data);
static void		xmlSecOpenSSLKeyDataRsaValueDebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecOpenSSLKeyDataRsaValueDebugXmlDump(xmlSecKeyDataPtr data,
								 FILE* output);
static RSA*		xmlSecOpenSSLRsaDup			(RSA* rsa);
static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataRsaValueKlass = {
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
    xmlSecOpenSSLKeyDataRsaValueInitialize,	/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataRsaValueDuplicate,	/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataRsaValueFinalize,	/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecOpenSSLKeyDataRsaValueGenerate,	/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecOpenSSLKeyDataRsaValueGetType, 	/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataRsaValueGetSize,	/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    xmlSecOpenSSLKeyDataRsaValueXmlRead,	/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataRsaValueXmlWrite,	/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,					/* xmlSecKeyDataBinReadMethod binRead; */
    NULL,					/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataRsaValueDebugDump,	/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataRsaValueDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

xmlSecKeyDataId 
xmlSecOpenSSLKeyDataRsaValueGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataRsaValueKlass);
}

int
xmlSecOpenSSLKeyDataRsaValueAdoptRsa(xmlSecKeyDataPtr data, RSA* rsa) {
    EVP_PKEY* pKey = NULL;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataRsaValueId), -1);
    
    /* construct new EVP_PKEY */
    if(rsa != NULL) {
	pKey = EVP_PKEY_new();
	if(pKey == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"EVP_PKEY_new");
	    return(-1);
	}
	
	ret = EVP_PKEY_assign_RSA(pKey, rsa);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"EVP_PKEY_assign_RSA");
	    return(-1);
	}	
    }
    
    ret = xmlSecOpenSSLKeyDataRsaValueAdoptEvp(data, pKey);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataRsaValueAdoptEvp");
	if(pKey != NULL) {
	    EVP_PKEY_free(pKey);
	}
	return(-1);
    }
    return(0);    
}

RSA* 
xmlSecOpenSSLKeyDataRsaValueGetRsa(xmlSecKeyDataPtr data) {
    EVP_PKEY* pKey;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataRsaValueId), NULL);
    
    pKey = xmlSecOpenSSLKeyDataRsaValueGetEvp(data);
    xmlSecAssert2((pKey == NULL) || (pKey->type == EVP_PKEY_RSA), NULL);
    
    return((pKey != NULL) ? pKey->pkey.rsa : (RSA*)NULL);
}

int 
xmlSecOpenSSLKeyDataRsaValueAdoptEvp(xmlSecKeyDataPtr data, EVP_PKEY* pKey) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataRsaValueId), -1);
    xmlSecAssert2((pKey == NULL) || (pKey->type == EVP_PKEY_RSA), -1);
    
    /* destroy the old one */
    if(data->reserved0 != NULL) {
	EVP_PKEY_free((EVP_PKEY*)(data->reserved0));
	data->reserved0 = NULL;
    }    
    
    data->reserved0 = pKey;
    return(0);
}

EVP_PKEY* 
xmlSecOpenSSLKeyDataRsaValueGetEvp(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataRsaValueId), NULL);

    return((EVP_PKEY*)(data->reserved0));
}

static int
xmlSecOpenSSLKeyDataRsaValueInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataRsaValueId), -1);

    return(0);
}

static int
xmlSecOpenSSLKeyDataRsaValueDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    EVP_PKEY* pKeySrc;
    EVP_PKEY* pKeyDst = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecKeyDataRsaValueId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecKeyDataRsaValueId), -1);

    pKeySrc = xmlSecOpenSSLKeyDataRsaValueGetEvp(src);
    if(pKeySrc != NULL) {
	pKeyDst = xmlSecOpenSSLEvpKeyDup(pKeySrc);
	if(pKeyDst == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLEvpDupKey");
	    return(-1);
	}	
    } 
    
    ret = xmlSecOpenSSLKeyDataRsaValueAdoptEvp(dst, pKeyDst);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataRsaValueAdoptEvp");
	EVP_PKEY_free(pKeyDst);
	return(-1);
    }

    return(0);
}

static void
xmlSecOpenSSLKeyDataRsaValueFinalize(xmlSecKeyDataPtr data) {
    int ret;
    
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecKeyDataRsaValueId));
    
    /* destroy buffer */
    ret = xmlSecOpenSSLKeyDataRsaValueAdoptEvp(data, NULL);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataRsaAdoptEvp");
    }
}

static int
xmlSecOpenSSLKeyDataRsaValueXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    xmlNodePtr cur;
    RSA *rsa;
    int ret;

    xmlSecAssert2(id == xmlSecKeyDataRsaValueId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA,
		    "key already has a value");
	return(-1);	
    }

    rsa = RSA_new();
    if(rsa == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "RSA_new");
	return(-1);
    }

    cur = xmlSecGetNextElementNode(node->children);
    
    /* first is Modulus node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  BAD_CAST "Modulus", xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "Modulus");
	RSA_free(rsa);	
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(rsa->n)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLNodeGetBNValue(Modulus)");
	RSA_free(rsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is Exponent node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "Exponent", xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "Exponent");
	RSA_free(rsa);
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(rsa->e)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLNodeGetBNValue(Exponent)");
	RSA_free(rsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "PrivateExponent", xmlSecNs))) {
        /* next is X node. It is REQUIRED for private key but
	 * we are not sure exactly what do we read */
	if(xmlSecOpenSSLNodeGetBNValue(cur, &(rsa->d)) == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLNodeGetBNValue(PrivateExponent)");
	    RSA_free(rsa);
	    return(-1);
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    (cur->name != NULL) ? (char*)cur->name : "NULL");
	RSA_free(rsa);
	return(-1);
    }

    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataInitialize");
	RSA_free(rsa);
	return(-1);
    }

    ret = xmlSecOpenSSLKeyDataRsaValueAdoptRsa(data, rsa);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataRsaValueAdopt");
	xmlSecKeyDataDestroy(data);
	RSA_free(rsa);
	return(-1);
    }

    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeySetValue");
	xmlSecKeyDataDestroy(data);
	return(-1);	
    }

    return(0);
}

static int 
xmlSecOpenSSLKeyDataRsaValueXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlNodePtr cur;
    RSA* rsa;
    int ret;
    
    xmlSecAssert2(id == xmlSecKeyDataRsaValueId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(key->value->id == id, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    rsa = xmlSecOpenSSLKeyDataRsaValueGetRsa(key->value);
    xmlSecAssert2(rsa != NULL, -1);
    
    if(((xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate) & keyInfoCtx->keyType) == 0) {
	/* we can have only private key or public key */
	return(0);
    }    

    /* first is Modulus node */
    cur = xmlSecAddChild(node, BAD_CAST "Modulus", xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(Modulus)");
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, rsa->n, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLNodeSetBNValue(Modulus)");
	return(-1);
    }    

    /* next is Exponent node. */
    cur = xmlSecAddChild(node, BAD_CAST "Exponent", xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(Exponent)");
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, rsa->e, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLNodeSetBNValue(Exponent)");
	return(-1);
    }

    /* next is PrivateExponent node: write it ONLY for private keys and ONLY if it is requested */
    if(((keyInfoCtx->keyType & xmlSecKeyDataTypePrivate) != 0) && (rsa->d != NULL)) {
	cur = xmlSecAddChild(node, BAD_CAST "PrivateExponent", xmlSecNs);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(PrivateExponent)");
	    return(-1);	
	}
	ret = xmlSecOpenSSLNodeSetBNValue(cur, rsa->d, 1);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLNodeSetBNValue(PrivateExponent)");
	    return(-1);
	}
    }
    
    return(0);
}

static int
xmlSecOpenSSLKeyDataRsaValueGenerate(xmlSecKeyDataPtr data, size_t sizeBits) {
    RSA* rsa;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataRsaValueId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    rsa = RSA_generate_key(sizeBits, 3, NULL, NULL); 
    if(rsa == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "RSA_generate_key(size=%d)", sizeBits);
	return(-1);    
    }

    ret = xmlSecOpenSSLKeyDataRsaValueAdoptRsa(data, rsa);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataRsaValueAdopt");
	RSA_free(rsa);
	return(-1);
    }

    return(0);
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataRsaValueGetType(xmlSecKeyDataPtr data) {
    RSA* rsa;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataRsaValueId), xmlSecKeyDataTypeUnknown);
    
    rsa = xmlSecOpenSSLKeyDataRsaValueGetRsa(data);
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
xmlSecOpenSSLKeyDataRsaValueGetSize(xmlSecKeyDataPtr data) {
    RSA* rsa;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataRsaValueId), 0);

    rsa = xmlSecOpenSSLKeyDataRsaValueGetRsa(data);
    if((rsa != NULL) && (rsa->n != NULL)) {
	return(BN_num_bits(rsa->n));
    }    
    return(0);
}

static void 
xmlSecOpenSSLKeyDataRsaValueDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecKeyDataRsaValueId));
    xmlSecAssert(output != NULL);
    
    fprintf(output, "=== rsa key: size = %d\n", 
	    xmlSecOpenSSLKeyDataRsaValueGetSize(data));
}

static void
xmlSecOpenSSLKeyDataRsaValueDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecKeyDataRsaValueId));
    xmlSecAssert(output != NULL);
        
    fprintf(output, "<RSAKeyValue size=\"%d\" />\n", 
	    xmlSecOpenSSLKeyDataRsaValueGetSize(data));
}

/****************************************************************************
 *
 * RSA-SHA1 signature transform
 *
 ***************************************************************************/
static xmlSecTransformPtr xmlSecOpenSSLRsaSha1Create		(xmlSecTransformId id);
static void 	xmlSecOpenSSLRsaSha1Destroy			(xmlSecTransformPtr transform);


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
    xmlSecNameRsaSha1,
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageSignatureMethod,/* xmlSecTransformUsage usage; */
    xmlSecHrefRsaSha1, 			/* xmlChar *href; */
    
    xmlSecOpenSSLRsaSha1Create,		/* xmlSecTransformCreateMethod create; */
    xmlSecOpenSSLRsaSha1Destroy,	/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadNodeMethod read; */
    xmlSecOpenSSLRsaSha1SetKeyReq,	/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLRsaSha1SetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLRsaSha1Verify,		/* xmlSecTransformVerifyMethod verify; */
    xmlSecOpenSSLRsaSha1Execute,	/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */

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

    keyInfoCtx->keyId 	     = xmlSecKeyDataRsaValueId;
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
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecKeyDataRsaValueId), -1);
    
    pKey = xmlSecOpenSSLKeyDataRsaValueGetEvp(key->value);
    if(pKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataRsaValueGetEvpKey");
	return(-1);
    }
    
    ret = xmlSecOpenSSLEvpSignatureSetKey(transform, pKey);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLEvpSignatureSetKey");
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

/****************************************************************************/

/**
 * xmlSecOpenSSLRsaSha1Create:
 */ 
static xmlSecTransformPtr 
xmlSecOpenSSLRsaSha1Create(xmlSecTransformId id) {
    xmlSecTransformPtr transform;
    int ret;
        
    xmlSecAssert2(id == xmlSecOpenSSLTransformRsaSha1Id, NULL);        
    
    transform = (xmlSecTransformPtr)xmlMalloc(sizeof(xmlSecTransform));
    if(transform == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", sizeof(xmlSecTransform));
	return(NULL);
    }

    memset(transform, 0, sizeof(xmlSecTransform));
    transform->id = id;

    ret = xmlSecOpenSSLRsaSha1Initialize(transform);	
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLRsaSha1Initialize");
	xmlSecTransformDestroy(transform, 1);
	return(NULL);
    }
    return(transform);
}

/**
 * xmlSecOpenSSLRsaSha1Destroy:
 */ 
static void 	
xmlSecOpenSSLRsaSha1Destroy(xmlSecTransformPtr transform) {

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha1Id));

    xmlSecOpenSSLRsaSha1Finalize(transform);

    memset(transform, 0, sizeof(xmlSecTransform));
    xmlFree(transform);
}


#include "rsa-old.c"

#endif /* XMLSEC_NO_RSA */

