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

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/digests.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
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
static int		xmlSecOpenSSLKeyDataDsaValueInitialize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataDsaValueDuplicate	(xmlSecKeyDataPtr dst,
								 xmlSecKeyDataPtr src);
static void		xmlSecOpenSSLKeyDataDsaValueFinalize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataDsaValueXmlRead	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataDsaValueXmlWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataDsaValueGenerate	(xmlSecKeyDataPtr data,
								 size_t sizeBits);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataDsaValueGetType	(xmlSecKeyDataPtr data);
static size_t		xmlSecOpenSSLKeyDataDsaValueGetSize	(xmlSecKeyDataPtr data);
static void		xmlSecOpenSSLKeyDataDsaValueDebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecOpenSSLKeyDataDsaValueDebugXmlDump(xmlSecKeyDataPtr data,
								 FILE* output);
static DSA*		xmlSecOpenSSLDsaDup			(DSA* dsa);
static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataDsaValueKlass = {
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
    xmlSecOpenSSLKeyDataDsaValueInitialize,	/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataDsaValueDuplicate,	/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataDsaValueFinalize,	/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecOpenSSLKeyDataDsaValueGenerate,	/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecOpenSSLKeyDataDsaValueGetType, 	/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataDsaValueGetSize,	/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    xmlSecOpenSSLKeyDataDsaValueXmlRead,	/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataDsaValueXmlWrite,	/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,					/* xmlSecKeyDataBinReadMethod binRead; */
    NULL,					/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataDsaValueDebugDump,	/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataDsaValueDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

xmlSecKeyDataId 
xmlSecOpenSSLKeyDataDsaValueGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataDsaValueKlass);
}

int
xmlSecOpenSSLKeyDataDsaValueSet(xmlSecKeyDataPtr data, DSA* dsa) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataDsaValueId), -1);

    /* destroy the old one */
    if(data->reserved0 != NULL) {
	DSA_free((DSA*)(data->reserved0));
	data->reserved0 = NULL;
    }    
    
    if(dsa != NULL) {
	data->reserved0 = xmlSecOpenSSLDsaDup(dsa);
	if(data->reserved0 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLDsaDup");
	    return(-1);
	}
    }
    return(0);    
}

DSA* 
xmlSecOpenSSLKeyDataDsaValueGet(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataDsaValueId), NULL);
    
    return((DSA*)(data->reserved0));
}

static DSA*
xmlSecOpenSSLDsaDup(DSA* dsa) {
    DSA* newDsa;
    
    xmlSecAssert2(dsa != NULL, NULL);

    /* increment reference counter instead of coping if possible */
#ifndef XMLSEC_OPENSSL096
    DSA_up_ref(dsa);
    newDsa =  dsa;
#else /* XMLSEC_OPENSSL096 */         
    newDsa = DSA_new();
    if(newDsa == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "DSA_new");
	return(NULL);
    }

    if(dsa->p != NULL) {
	newDsa->p = BN_dup(dsa->p);
    }
    if(dsa->q != NULL) {
	newDsa->q = BN_dup(dsa->q);
    }
    if(dsa->g != NULL) {
	newDsa->g = BN_dup(dsa->g);
    }
    if(dsa->priv_key != NULL) {
	newDsa->priv_key = BN_dup(dsa->priv_key);
    }
    if(dsa->pub_key != NULL) {
	newDsa->pub_key = BN_dup(dsa->pub_key);
    }
#endif /* XMLSEC_OPENSSL096 */         

    return(newDsa);
}

static int
xmlSecOpenSSLKeyDataDsaValueInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataDsaValueId), -1);

    return(0);
}

static int
xmlSecOpenSSLKeyDataDsaValueDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecKeyDataDsaValueId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecKeyDataDsaValueId), -1);

    /* copy data */    
    ret = xmlSecOpenSSLKeyDataDsaValueSet(dst, xmlSecOpenSSLKeyDataDsaValueGet(src));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataDsaValueSet");
	return(-1);
    }

    return(0);
}

static void
xmlSecOpenSSLKeyDataDsaValueFinalize(xmlSecKeyDataPtr data) {
    int ret;
    
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecKeyDataDsaValueId));
    
    /* destroy buffer */
    ret = xmlSecOpenSSLKeyDataDsaValueSet(data, NULL);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataDsaValueSet");
    }
}

static int
xmlSecOpenSSLKeyDataDsaValueXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    xmlNodePtr cur;
    DSA *dsa;
    int ret;

    xmlSecAssert2(id == xmlSecKeyDataDsaValueId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA,
		    "key already has a value");
	return(-1);	
    }

    dsa = DSA_new();
    if(dsa == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "DSA_new");
	return(-1);
    }
    
    cur = xmlSecGetNextElementNode(node->children);

    /* first is P node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  BAD_CAST "P", xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "P");
	DSA_free(dsa);	
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(dsa->p)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLNodeGetBNValue");
	DSA_free(dsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is Q node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "Q", xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "Q");
	DSA_free(dsa);
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(dsa->q)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLNodeGetBNValue");
	DSA_free(dsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is G node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "G", xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "G");
	DSA_free(dsa);
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(dsa->g)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLNodeGetBNValue");
	DSA_free(dsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "X", xmlSecNs))) {
        /* next is X node. It is REQUIRED for private key but
	 * we are not sure exactly what do we read */
	if(xmlSecOpenSSLNodeGetBNValue(cur, &(dsa->priv_key)) == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLNodeGetBNValue");
	    DSA_free(dsa);
	    return(-1);
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next is Y node. */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "Y", xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "Y");
	DSA_free(dsa);
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(dsa->pub_key)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLNodeGetBNValue");
	DSA_free(dsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);
    
    /* todo: add support for seed */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "Seed", xmlSecDSigNs))) {
	cur = xmlSecGetNextElementNode(cur->next);  
    }

    /* todo: add support for pgencounter */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "PgenCounter", xmlSecDSigNs))) {
	cur = xmlSecGetNextElementNode(cur->next);  
    }

    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "%s", (cur->name != NULL) ? (char*)cur->name : "NULL");
	DSA_free(dsa);
	return(-1);
    }

    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataCreate");
	DSA_free(dsa);
	return(-1);
    }

    ret = xmlSecOpenSSLKeyDataDsaValueSet(data, dsa);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataDsaValueSet");
	xmlSecKeyDataDestroy(data);
	DSA_free(dsa);
	return(-1);
    }

    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeySetValue");
	xmlSecKeyDataDestroy(data);
	DSA_free(dsa);
	return(-1);	
    }
    DSA_free(dsa);

    return(0);
}

static int 
xmlSecOpenSSLKeyDataDsaValueXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlNodePtr cur;
    DSA* dsa;
    int ret;
    
    xmlSecAssert2(id == xmlSecKeyDataDsaValueId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(key->value->id == id, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    dsa = xmlSecOpenSSLKeyDataDsaValueGet(key->value);
    xmlSecAssert2(dsa != NULL, -1);
    
    if(((xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate) & keyInfoCtx->keyType) == 0) {
	/* we can have only private key or public key */
	return(0);
    }    
    
    /* first is P node */
    xmlSecAssert2(dsa->p != NULL, -1);
    cur = xmlSecAddChild(node, BAD_CAST "P", xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"P\")");
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, dsa->p, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLNodeSetBNValue - %d", ret);
	return(-1);
    }    

    /* next is Q node. */
    xmlSecAssert2(dsa->q != NULL, -1);
    cur = xmlSecAddChild(node, BAD_CAST "Q", xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"Q\")");	
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, dsa->q, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLNodeSetBNValue - %d", ret);
	return(-1);
    }

    /* next is G node. */
    xmlSecAssert2(dsa->g != NULL, -1);
    cur = xmlSecAddChild(node, BAD_CAST "G", xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"G\")");	
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, dsa->g, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLNodeSetBNValue - %d", ret);
	return(-1);
    }

    /* next is X node: write it ONLY for private keys and ONLY if it is requested */
    if(((keyInfoCtx->keyType & xmlSecKeyDataTypePrivate) != 0) && (dsa->priv_key != NULL)) {
	cur = xmlSecAddChild(node, BAD_CAST "X", xmlSecNs);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(\"X\")");	
	    return(-1);	
	}
	ret = xmlSecOpenSSLNodeSetBNValue(cur, dsa->priv_key, 1);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLNodeSetBNValue - %d", ret);
	    return(-1);
	}
    }

    /* next is Y node. */
    xmlSecAssert2(dsa->pub_key != NULL, -1);
    cur = xmlSecAddChild(node, BAD_CAST "Y", xmlSecDSigNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"Y\")");	
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, dsa->pub_key, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLNodeSetBNValue - %d", ret);
	return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLKeyDataDsaValueGenerate(xmlSecKeyDataPtr data, size_t sizeBits) {
    DSA* dsa;
    int counter_ret;
    unsigned long h_ret;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataDsaValueId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    dsa = DSA_generate_parameters(sizeBits, NULL, 0, &counter_ret, &h_ret, NULL, NULL); 
    if(dsa == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "DSA_generate_parameters(size=%d)", sizeBits);
	return(-1);    
    }

    ret = DSA_generate_key(dsa);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "DSA_generate_key - %d", ret);
	DSA_free(dsa);
	return(-1);    
    }

    ret = xmlSecOpenSSLKeyDataDsaValueSet(data, dsa);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataDsaValueSet");
	DSA_free(dsa);
	return(-1);
    }

    return(0);
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataDsaValueGetType(xmlSecKeyDataPtr data) {
    DSA* dsa;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataDsaValueId), xmlSecKeyDataTypeUnknown);
    
    dsa = xmlSecOpenSSLKeyDataDsaValueGet(data);
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
xmlSecOpenSSLKeyDataDsaValueGetSize(xmlSecKeyDataPtr data) {
    DSA* dsa;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataDsaValueId), 0);

    dsa = xmlSecOpenSSLKeyDataDsaValueGet(data);
    if((dsa != NULL) && (dsa->p != NULL)) {
	return(BN_num_bits(dsa->p));
    }    
    return(0);
}

static void 
xmlSecOpenSSLKeyDataDsaValueDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecKeyDataDsaValueId));
    xmlSecAssert(output != NULL);
    
    fprintf(output, "=== dsa key: size = %d\n", 
	    xmlSecOpenSSLKeyDataDsaValueGetSize(data));
}

static void
xmlSecOpenSSLKeyDataDsaValueDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecKeyDataDsaValueId));
    xmlSecAssert(output != NULL);
        
    fprintf(output, "<DSAKeyValue size=\"%d\" />\n", 
	    xmlSecOpenSSLKeyDataDsaValueGetSize(data));
}

#include "dsa-old.c"

#endif /* XMLSEC_NO_DSA */

