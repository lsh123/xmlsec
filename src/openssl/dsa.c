/** 
 *
 * XMLSec library
 * 
 * DSA Algorithm support
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_DSA

#include <stdlib.h>
#include <string.h>

#include <openssl/dsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/openssl/bn.h>

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
static int		xmlSecOpenSSLKeyDataDsaInitialize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataDsaDuplicate	(xmlSecKeyDataPtr dst,
								 xmlSecKeyDataPtr src);
static void		xmlSecOpenSSLKeyDataDsaFinalize		(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataDsaXmlRead		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataDsaXmlWrite		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataDsaGenerate		(xmlSecKeyDataPtr data,
								 size_t sizeBits);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataDsaGetType		(xmlSecKeyDataPtr data);
static size_t		xmlSecOpenSSLKeyDataDsaGetSize		(xmlSecKeyDataPtr data);
static void		xmlSecOpenSSLKeyDataDsaDebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecOpenSSLKeyDataDsaDebugXmlDump	(xmlSecKeyDataPtr data,
								 FILE* output);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataDsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),

    /* data */
    xmlSecNameDSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefDSAKeyValue,			/* const xmlChar* href; */
    xmlSecNodeDSAKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecDSigNs,				/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecOpenSSLKeyDataDsaInitialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataDsaDuplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataDsaFinalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecOpenSSLKeyDataDsaGenerate,		/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecOpenSSLKeyDataDsaGetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataDsaGetSize,		/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    xmlSecOpenSSLKeyDataDsaXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataDsaXmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,					/* xmlSecKeyDataBinReadMethod binRead; */
    NULL,					/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataDsaDebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataDsaDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

xmlSecKeyDataId 
xmlSecOpenSSLKeyDataDsaGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataDsaKlass);
}

int
xmlSecOpenSSLKeyDataDsaAdoptDsa(xmlSecKeyDataPtr data, DSA* dsa) {
    EVP_PKEY* pKey = NULL;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);
    
    /* construct new EVP_PKEY */
    if(dsa != NULL) {
	pKey = EVP_PKEY_new();
	if(pKey == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			"EVP_PKEY_new",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	
	ret = EVP_PKEY_assign_DSA(pKey, dsa);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
			"EVP_PKEY_assign_DSA",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}	
    }
    
    ret = xmlSecOpenSSLKeyDataDsaAdoptEvp(data, pKey);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecOpenSSLKeyDataDsaAdoptEvp",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	if(pKey != NULL) {
	    EVP_PKEY_free(pKey);
	}
	return(-1);
    }
    return(0);    
}

DSA* 
xmlSecOpenSSLKeyDataDsaGetDsa(xmlSecKeyDataPtr data) {
    EVP_PKEY* pKey;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), NULL);
    
    pKey = xmlSecOpenSSLKeyDataDsaGetEvp(data);
    xmlSecAssert2((pKey == NULL) || (pKey->type == EVP_PKEY_DSA), NULL);
    
    return((pKey != NULL) ? pKey->pkey.dsa : (DSA*)NULL);
}

int 
xmlSecOpenSSLKeyDataDsaAdoptEvp(xmlSecKeyDataPtr data, EVP_PKEY* pKey) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2((pKey == NULL) || (pKey->type == EVP_PKEY_DSA), -1);
    
    /* finalize the old one */
    if(data->reserved0 != NULL) {
	EVP_PKEY_free((EVP_PKEY*)(data->reserved0));
	data->reserved0 = NULL;
    }    
    
    data->reserved0 = pKey;
    return(0);
}

EVP_PKEY* 
xmlSecOpenSSLKeyDataDsaGetEvp(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), NULL);

    return((EVP_PKEY*)(data->reserved0));
}

static int
xmlSecOpenSSLKeyDataDsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);

    return(0);
}

static int
xmlSecOpenSSLKeyDataDsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    EVP_PKEY* pKeySrc;
    EVP_PKEY* pKeyDst = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataDsaId), -1);

    pKeySrc = xmlSecOpenSSLKeyDataDsaGetEvp(src);
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
    
    ret = xmlSecOpenSSLKeyDataDsaAdoptEvp(dst, pKeyDst);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
		    "xmlSecOpenSSLKeyDataDsaAdoptEvp",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	EVP_PKEY_free(pKeyDst);
	return(-1);
    }

    return(0);
}

static void
xmlSecOpenSSLKeyDataDsaFinalize(xmlSecKeyDataPtr data) {
    int ret;
    
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId));
    
    /* finalize buffer */
    ret = xmlSecOpenSSLKeyDataDsaAdoptEvp(data, NULL);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecOpenSSLKeyDataDsaAdoptEvp",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
    }
}

static int
xmlSecOpenSSLKeyDataDsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    xmlNodePtr cur;
    DSA *dsa;
    int ret;

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecKeyGetValue",
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }

    dsa = DSA_new();
    if(dsa == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "DSA_new",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    cur = xmlSecGetNextElementNode(node->children);

    /* first is P node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  xmlSecNodeDSAP, xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecNodeGetName(cur),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAP));
	DSA_free(dsa);	
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(dsa->p)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeGetBNValue",		    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAP));
	DSA_free(dsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is Q node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAQ, xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecNodeGetName(cur),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAQ));
	DSA_free(dsa);
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(dsa->q)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeGetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAQ));
	DSA_free(dsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is G node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAG, xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecNodeGetName(cur),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAG));
	DSA_free(dsa);
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(dsa->g)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeGetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAG));
	DSA_free(dsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAX, xmlSecNs))) {
        /* next is X node. It is REQUIRED for private key but
	 * we are not sure exactly what do we read */
	if(xmlSecOpenSSLNodeGetBNValue(cur, &(dsa->priv_key)) == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecOpenSSLNodeGetBNValue",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"%s", xmlSecErrorsSafeString(xmlSecNodeDSAX));
	    DSA_free(dsa);
	    return(-1);
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next is Y node. */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAY, xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecNodeGetName(cur),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAY));
	DSA_free(dsa);
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(dsa->pub_key)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeGetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAY));
	DSA_free(dsa);
	return(-1);
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
		    xmlSecNodeGetName(cur),
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	DSA_free(dsa);
	return(-1);
    }

    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecKeyDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	DSA_free(dsa);
	return(-1);
    }

    ret = xmlSecOpenSSLKeyDataDsaAdoptDsa(data, dsa);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecOpenSSLKeyDataDsaAdoptDsa",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyDataDestroy(data);
	DSA_free(dsa);
	return(-1);
    }

    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecKeySetValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyDataDestroy(data);
	return(-1);	
    }

    return(0);
}

static int 
xmlSecOpenSSLKeyDataDsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlNodePtr cur;
    DSA* dsa;
    int ret;
    
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    dsa = xmlSecOpenSSLKeyDataDsaGetDsa(xmlSecKeyGetValue(key));
    xmlSecAssert2(dsa != NULL, -1);
    
    if(((xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate) & keyInfoCtx->keyType) == 0) {
	/* we can have only private key or public key */
	return(0);
    }    
    
    /* first is P node */
    xmlSecAssert2(dsa->p != NULL, -1);
    cur = xmlSecAddChild(node, xmlSecNodeDSAP, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAP));
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, dsa->p, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeSetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAP));
	return(-1);
    }    

    /* next is Q node. */
    xmlSecAssert2(dsa->q != NULL, -1);
    cur = xmlSecAddChild(node, xmlSecNodeDSAQ, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAQ));
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, dsa->q, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeSetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAQ));
	return(-1);
    }

    /* next is G node. */
    xmlSecAssert2(dsa->g != NULL, -1);
    cur = xmlSecAddChild(node, xmlSecNodeDSAG, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAG));
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, dsa->g, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeSetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAG));
	return(-1);
    }

    /* next is X node: write it ONLY for private keys and ONLY if it is requested */
    if(((keyInfoCtx->keyType & xmlSecKeyDataTypePrivate) != 0) && (dsa->priv_key != NULL)) {
	cur = xmlSecAddChild(node, xmlSecNodeDSAX, xmlSecNs);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecAddChild",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"%s", xmlSecErrorsSafeString(xmlSecNodeDSAX));
	    return(-1);	
	}
	ret = xmlSecOpenSSLNodeSetBNValue(cur, dsa->priv_key, 1);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecOpenSSLNodeSetBNValue",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"%s", xmlSecErrorsSafeString(xmlSecNodeDSAX));
	    return(-1);
	}
    }

    /* next is Y node. */
    xmlSecAssert2(dsa->pub_key != NULL, -1);
    cur = xmlSecAddChild(node, xmlSecNodeDSAY, xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAY));
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, dsa->pub_key, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeSetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", xmlSecErrorsSafeString(xmlSecNodeDSAY));
	return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLKeyDataDsaGenerate(xmlSecKeyDataPtr data, size_t sizeBits) {
    DSA* dsa;
    int counter_ret;
    unsigned long h_ret;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    dsa = DSA_generate_parameters(sizeBits, NULL, 0, &counter_ret, &h_ret, NULL, NULL); 
    if(dsa == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "DSA_generate_parameters",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "size=%d", sizeBits);
	return(-1);    
    }

    ret = DSA_generate_key(dsa);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "DSA_generate_key",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	DSA_free(dsa);
	return(-1);    
    }

    ret = xmlSecOpenSSLKeyDataDsaAdoptDsa(data, dsa);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
		    "xmlSecOpenSSLKeyDataDsaAdoptDsa",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	DSA_free(dsa);
	return(-1);
    }

    return(0);
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataDsaGetType(xmlSecKeyDataPtr data) {
    DSA* dsa;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), xmlSecKeyDataTypeUnknown);
    
    dsa = xmlSecOpenSSLKeyDataDsaGetDsa(data);
    if((dsa != NULL) && (dsa->p != NULL) && (dsa->q != NULL) && 
       (dsa->g != NULL) && (dsa->pub_key != NULL)) {
       
        if(dsa->priv_key != NULL) {
	    return(xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
	} else {
	    return(xmlSecKeyDataTypePublic);
	}
    }

    return(xmlSecKeyDataTypeUnknown);
}

static size_t 
xmlSecOpenSSLKeyDataDsaGetSize(xmlSecKeyDataPtr data) {
    DSA* dsa;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), 0);

    dsa = xmlSecOpenSSLKeyDataDsaGetDsa(data);
    if((dsa != NULL) && (dsa->p != NULL)) {
	return(BN_num_bits(dsa->p));
    }    
    return(0);
}

static void 
xmlSecOpenSSLKeyDataDsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId));
    xmlSecAssert(output != NULL);
    
    fprintf(output, "=== dsa key: size = %d\n", 
	    xmlSecOpenSSLKeyDataDsaGetSize(data));
}

static void
xmlSecOpenSSLKeyDataDsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId));
    xmlSecAssert(output != NULL);
        
    fprintf(output, "<DSAKeyValue size=\"%d\" />\n", 
	    xmlSecOpenSSLKeyDataDsaGetSize(data));
}

/****************************************************************************
 *
 * DSA-SHA1 signature transform
 *
 ***************************************************************************/
static int 	xmlSecOpenSSLDsaSha1Initialize			(xmlSecTransformPtr transform);
static void 	xmlSecOpenSSLDsaSha1Finalize			(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLDsaSha1SetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecOpenSSLDsaSha1SetKey			(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecOpenSSLDsaSha1Verify			(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
								 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecOpenSSLDsaSha1Execute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);


static const EVP_MD *xmlSecOpenSSLDsaEvp			(void);

static xmlSecTransformKlass xmlSecOpenSSLDsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    xmlSecOpenSSLEvpSignatureSize,	/* size_t objSize */

    xmlSecNameDsaSha1,
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageSignatureMethod,/* xmlSecTransformUsage usage; */
    xmlSecHrefDsaSha1, 			/* xmlChar *href; */
    
    xmlSecOpenSSLDsaSha1Initialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLDsaSha1Finalize,	/* xmlSecTransformFinalizeMethod finalize; */
    NULL,				/* xmlSecTransformReadNodeMethod read; */
    xmlSecOpenSSLDsaSha1SetKeyReq,	/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLDsaSha1SetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLDsaSha1Verify,		/* xmlSecTransformVerifyMethod verify; */
    xmlSecOpenSSLDsaSha1Execute,	/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

xmlSecTransformId 
xmlSecOpenSSLTransformDsaSha1GetKlass(void) {
    return(&xmlSecOpenSSLDsaSha1Klass);
}


static int 
xmlSecOpenSSLDsaSha1Initialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha1Id), -1);
    
    return(xmlSecOpenSSLEvpSignatureInitialize(transform, xmlSecOpenSSLDsaEvp()));
}

static void 
xmlSecOpenSSLDsaSha1Finalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha1Id));

    xmlSecOpenSSLEvpSignatureFinalize(transform);
}

static int  
xmlSecOpenSSLDsaSha1SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha1Id), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	     = xmlSecOpenSSLKeyDataDsaId;
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
xmlSecOpenSSLDsaSha1SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    EVP_PKEY* pKey;
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha1Id), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataDsaId), -1);
    
    pKey = xmlSecOpenSSLKeyDataDsaGetEvp(xmlSecKeyGetValue(key));
    if(pKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLKeyDataDsaGetEvp",
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
xmlSecOpenSSLDsaSha1Verify(xmlSecTransformPtr transform, const unsigned char* data,
		    size_t dataSize, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha1Id), -1);

    return(xmlSecOpenSSLEvpSignatureVerify(transform, data, dataSize, transformCtx));
}

static int 
xmlSecOpenSSLDsaSha1Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha1Id), -1);
    
    return(xmlSecOpenSSLEvpSignatureExecute(transform, last, transformCtx));
}

/****************************************************************************
 *
 * DSA-SHA1 EVP
 *
 * XMLDSig specifies dsa signature packing not supported by OpenSSL so 
 * we created our own EVP_MD.
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-SignatureAlg:
 * 
 * The output of the DSA algorithm consists of a pair of integers 
 * usually referred by the pair (r, s). The signature value consists of 
 * the base64 encoding of the concatenation of two octet-streams that 
 * respectively result from the octet-encoding of the values r and s in 
 * that order. Integer to octet-stream conversion must be done according 
 * to the I2OSP operation defined in the RFC 2437 [PKCS1] specification 
 * with a l parameter equal to 20. For example, the SignatureValue element 
 * for a DSA signature (r, s) with values specified in hexadecimal:
 *
 *  r = 8BAC1AB6 6410435C B7181F95 B16AB97C 92B341C0 
 *  s = 41E2345F 1F56DF24 58F426D1 55B4BA2D B6DCD8C8
 *       
 * from the example in Appendix 5 of the DSS standard would be
 *        
 * <SignatureValue>i6watmQQQ1y3GB+VsWq5fJKzQcBB4jRfH1bfJFj0JtFVtLotttzYyA==</SignatureValue>
 *
 ***************************************************************************/
static int 
xmlSecOpenSSLDsaEvpInit(EVP_MD_CTX *ctx)
{ 
    return SHA1_Init(ctx->md_data); 
}

static int 
xmlSecOpenSSLDsaEvpUpdate(EVP_MD_CTX *ctx,const void *data,unsigned long count)
{ 
    return SHA1_Update(ctx->md_data,data,count); 
}

static int 
xmlSecOpenSSLDsaEvpFinal(EVP_MD_CTX *ctx,unsigned char *md)
{ 
    return SHA1_Final(md,ctx->md_data); 
}

static int 	
xmlSecOpenSSLDsaEvpSign(int type ATTRIBUTE_UNUSED, 
			const unsigned char *dgst, int dlen,
			unsigned char *sig, unsigned int *siglen, DSA *dsa) {
    DSA_SIG *s;
    int rSize, sSize;

    s = DSA_do_sign(dgst, dlen, dsa);
    if(s == NULL) {
	*siglen=0;
	return(0);
    }

    rSize = BN_num_bytes(s->r);
    sSize = BN_num_bytes(s->s);
    if((rSize > (XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE / 2)) ||
       (sSize > (XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE / 2))) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "size(r)=%d or size(s)=%d > %d", 
		    rSize, sSize, XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE / 2);
	DSA_SIG_free(s);
	return(0);
    }	

    memset(sig, 0, XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE);
    BN_bn2bin(s->r, sig + (XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE / 2) - rSize);
    BN_bn2bin(s->s, sig + XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE - sSize);
    *siglen = XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE;

    DSA_SIG_free(s);
    return(1);    
}

static int 
xmlSecOpenSSLDsaEvpVerify(int type ATTRIBUTE_UNUSED, 
			const unsigned char *dgst, int dgst_len,
			const unsigned char *sigbuf, int siglen, DSA *dsa) {
    DSA_SIG *s;    
    int ret = -1;

    s = DSA_SIG_new();
    if (s == NULL) {
	return(ret);
    }

    if(siglen != XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "invalid length %d (%d expected)",
		    siglen, XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE);
	goto err;
    }

    s->r = BN_bin2bn(sigbuf, XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE / 2, NULL);
    s->s = BN_bin2bn(sigbuf + (XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE / 2), 
		       XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE / 2, NULL);
    if((s->r == NULL) || (s->s == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "BN_bin2bn",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto err;
    }

    ret = DSA_do_verify(dgst, dgst_len, s, dsa);

err:
    DSA_SIG_free(s);
    return(ret);
}

static const EVP_MD xmlSecOpenSSLDsaMdEvp = {
    NID_dsaWithSHA,
    NID_dsaWithSHA,
    SHA_DIGEST_LENGTH,
    0,
    xmlSecOpenSSLDsaEvpInit,
    xmlSecOpenSSLDsaEvpUpdate,
    xmlSecOpenSSLDsaEvpFinal,
    NULL,
    NULL,
    xmlSecOpenSSLDsaEvpSign,
    xmlSecOpenSSLDsaEvpVerify, 
    {EVP_PKEY_DSA,EVP_PKEY_DSA2,EVP_PKEY_DSA3,EVP_PKEY_DSA4,0},
    SHA_CBLOCK,
    sizeof(EVP_MD *)+sizeof(SHA_CTX),
};

static const EVP_MD *xmlSecOpenSSLDsaEvp(void)
{
    return(&xmlSecOpenSSLDsaMdEvp);
}

#endif /* XMLSEC_NO_DSA */

