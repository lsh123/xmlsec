/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/bn.h>
#include <xmlsec/openssl/evp.h>

/**************************************************************************
 *
 * Internal OpenSSL EVP key CTX
 *
 *************************************************************************/
typedef struct _xmlSecOpenSSLEvpKeyDataCtx	xmlSecOpenSSLEvpKeyDataCtx, 
						*xmlSecOpenSSLEvpKeyDataCtxPtr;
struct _xmlSecOpenSSLEvpKeyDataCtx {
    EVP_PKEY*		pKey;
};	    

/******************************************************************************
 *
 * EVP key (dsa/rsa)
 *
 * xmlSecOpenSSLEvpKeyDataCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecOpenSSLEvpKeyDataSize	\
    (sizeof(xmlSecKeyData) + sizeof(xmlSecOpenSSLEvpKeyDataCtx))	
#define xmlSecOpenSSLEvpKeyDataGetCtx(data) \
    ((xmlSecOpenSSLEvpKeyDataCtxPtr)(((xmlSecByte*)(data)) + sizeof(xmlSecKeyData)))

static int		xmlSecOpenSSLEvpKeyDataInitialize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLEvpKeyDataDuplicate	(xmlSecKeyDataPtr dst,
								 xmlSecKeyDataPtr src);
static void		xmlSecOpenSSLEvpKeyDataFinalize		(xmlSecKeyDataPtr data);

/**
 * xmlSecOpenSSLEvpKeyDataAdoptEvp:
 * @data:		the pointer to OpenSSL EVP key data.
 * @pKey:		the pointer to EVP key.
 *
 * Sets the value of key data.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecOpenSSLEvpKeyDataAdoptEvp(xmlSecKeyDataPtr data, EVP_PKEY* pKey) {
    xmlSecOpenSSLEvpKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecOpenSSLEvpKeyDataSize), -1);
    xmlSecAssert2(pKey != NULL, -1);
    
    ctx = xmlSecOpenSSLEvpKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    
    if(ctx->pKey != NULL) {
	EVP_PKEY_free(ctx->pKey);
    }
    ctx->pKey = pKey;
    return(0);
}

/**
 * xmlSecOpenSSLEvpKeyDataGetEvp:
 * @data:		the pointer to OpenSSL EVP data.
 *
 * Gets the EVP_PKEY from the key data.
 *
 * Returns pointer to EVP_PKEY or NULL if an error occurs.
 */
EVP_PKEY* 
xmlSecOpenSSLEvpKeyDataGetEvp(xmlSecKeyDataPtr data) {
    xmlSecOpenSSLEvpKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecOpenSSLEvpKeyDataSize), NULL);

    ctx = xmlSecOpenSSLEvpKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->pKey);
}

static int
xmlSecOpenSSLEvpKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecOpenSSLEvpKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecOpenSSLEvpKeyDataSize), -1);

    ctx = xmlSecOpenSSLEvpKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLEvpKeyDataCtx));

    return(0);
}

static int
xmlSecOpenSSLEvpKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecOpenSSLEvpKeyDataCtxPtr ctxDst;
    xmlSecOpenSSLEvpKeyDataCtxPtr ctxSrc;

    xmlSecAssert2(xmlSecKeyDataIsValid(dst), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(dst, xmlSecOpenSSLEvpKeyDataSize), -1);
    xmlSecAssert2(xmlSecKeyDataIsValid(src), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(src, xmlSecOpenSSLEvpKeyDataSize), -1);

    ctxDst = xmlSecOpenSSLEvpKeyDataGetCtx(dst);
    xmlSecAssert2(ctxDst != NULL, -1);
    xmlSecAssert2(ctxDst->pKey == NULL, -1);

    ctxSrc = xmlSecOpenSSLEvpKeyDataGetCtx(src);
    xmlSecAssert2(ctxSrc != NULL, -1);

    if(ctxSrc->pKey != NULL) {
	ctxDst->pKey = xmlSecOpenSSLEvpKeyDup(ctxSrc->pKey);
	if(ctxDst->pKey == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
			"xmlSecOpenSSLEvpKeyDup",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}	
    } 

    return(0);
}

static void
xmlSecOpenSSLEvpKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecOpenSSLEvpKeyDataCtxPtr ctx;
    
    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecOpenSSLEvpKeyDataSize));

    ctx = xmlSecOpenSSLEvpKeyDataGetCtx(data);
    xmlSecAssert(ctx != NULL);
    
    if(ctx->pKey != NULL) {
	EVP_PKEY_free(ctx->pKey);
    }
    memset(ctx, 0, sizeof(xmlSecOpenSSLEvpKeyDataCtx));
}

/******************************************************************************
 *
 * EVP helper functions
 *
 *****************************************************************************/
/**
 * xmlSecOpenSSLEvpKeyDup:
 * @pKey:		the pointer to EVP_PKEY.
 *
 * Duplicates @pKey.
 *
 * Returns pointer to newly created EVP_PKEY object or NULL if an error occurs.
 */
EVP_PKEY* 
xmlSecOpenSSLEvpKeyDup(EVP_PKEY* pKey) {
    int ret;

    xmlSecAssert2(pKey != NULL, NULL);
    
    ret = CRYPTO_add(&pKey->references,1,CRYPTO_LOCK_EVP_PKEY);
    if(ret <= 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "CRYPTO_add",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);		    	
    }
    
    return(pKey);
}

/**
 * xmlSecOpenSSLEvpKeyAdopt:
 * @pKey:		the pointer to EVP_PKEY.
 *
 * Creates xmlsec key object from OpenSSL key object.
 *
 * Returns pointer to newly created xmlsec key or NULL if an error occurs.
 */
xmlSecKeyDataPtr
xmlSecOpenSSLEvpKeyAdopt(EVP_PKEY *pKey) {
    xmlSecKeyDataPtr data = NULL;
    int ret;
    
    xmlSecAssert2(pKey != NULL, NULL);

    switch(pKey->type) {	
#ifndef XMLSEC_NO_RSA    
    case EVP_PKEY_RSA:
	data = xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataRsaId);
	if(data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeyDataCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataRsaId");
	    return(NULL);	    
	}
	break;
#endif /* XMLSEC_NO_RSA */	
#ifndef XMLSEC_NO_DSA	
    case EVP_PKEY_DSA:
	data = xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataDsaId);
	if(data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeyDataCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataDsaId");
	    return(NULL);	    
	}
	break;
#endif /* XMLSEC_NO_DSA */	
    default:	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "evp key type %d not supported", pKey->type);
	return(NULL);
    }

    xmlSecAssert2(data != NULL, NULL);    
    ret = xmlSecOpenSSLEvpKeyDataAdoptEvp(data, pKey);
    if(ret < 0) {	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecOpenSSLEvpKeyDataAdoptEvp",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyDataDestroy(data);
	return(NULL);	    
    }
    return(data);
}

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
								 xmlSecSize sizeBits,
								 xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataDsaGetType		(xmlSecKeyDataPtr data);
static xmlSecSize		xmlSecOpenSSLKeyDataDsaGetSize		(xmlSecKeyDataPtr data);
static void		xmlSecOpenSSLKeyDataDsaDebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecOpenSSLKeyDataDsaDebugXmlDump	(xmlSecKeyDataPtr data,
								 FILE* output);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataDsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecOpenSSLEvpKeyDataSize,

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

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecOpenSSLKeyDataDsaGetKlass:
 * 
 * The DSA key data klass.
 *
 * Returns pointer to DSA key data klass.
 */
xmlSecKeyDataId 
xmlSecOpenSSLKeyDataDsaGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataDsaKlass);
}

/**
 * xmlSecOpenSSLKeyDataDsaAdoptDsa:
 * @data:		the pointer to DSA key data.
 * @dsa:		the pointer to OpenSSL DSA key.
 *
 * Sets the value of DSA key data.
 *
 * Returns 0 on success or a negative value otherwise.
 */ 
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

/**
 * xmlSecOpenSSLKeyDataDsaGetDsa:
 * @data:		the pointer to DSA key data.
 *
 * Gets the OpenSSL DSA key from DSA key data.
 *
 * Returns pointer to OpenSSL DSA key or NULL if an error occurs.
 */
DSA* 
xmlSecOpenSSLKeyDataDsaGetDsa(xmlSecKeyDataPtr data) {
    EVP_PKEY* pKey;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), NULL);
    
    pKey = xmlSecOpenSSLKeyDataDsaGetEvp(data);
    xmlSecAssert2((pKey == NULL) || (pKey->type == EVP_PKEY_DSA), NULL);
    
    return((pKey != NULL) ? pKey->pkey.dsa : (DSA*)NULL);
}

/** 
 * xmlSecOpenSSLKeyDataDsaAdoptEvp:
 * @data:		the pointer to DSA key data.
 * @pKey:		the pointer to OpenSSL EVP key.
 *
 * Sets the DSA key data value to OpenSSL EVP key.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecOpenSSLKeyDataDsaAdoptEvp(xmlSecKeyDataPtr data, EVP_PKEY* pKey) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2(pKey != NULL, -1);
    xmlSecAssert2(pKey->type == EVP_PKEY_DSA, -1);
    
    return(xmlSecOpenSSLEvpKeyDataAdoptEvp(data, pKey));
}

/**
 * xmlSecOpenSSLKeyDataDsaGetEvp:
 * @data:		the pointer to DSA key data.
 *
 * Gets the OpenSSL EVP key from DSA key data.
 *
 * Returns pointer to OpenSSL EVP key or NULL if an error occurs.
 */
EVP_PKEY* 
xmlSecOpenSSLKeyDataDsaGetEvp(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), NULL);

    return(xmlSecOpenSSLEvpKeyDataGetEvp(data));
}

static int
xmlSecOpenSSLKeyDataDsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);

    return(xmlSecOpenSSLEvpKeyDataInitialize(data));
}

static int
xmlSecOpenSSLKeyDataDsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataDsaId), -1);

    return(xmlSecOpenSSLEvpKeyDataDuplicate(dst, src));
}

static void
xmlSecOpenSSLKeyDataDsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId));
    
    xmlSecOpenSSLEvpKeyDataFinalize(data);
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
		    NULL,
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
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAP));
	DSA_free(dsa);	
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(dsa->p)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeGetBNValue",		    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAP));
	DSA_free(dsa);
	return(-1);
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
	DSA_free(dsa);
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(dsa->q)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeGetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAQ));
	DSA_free(dsa);
	return(-1);
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
	DSA_free(dsa);
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(dsa->g)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeGetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAG));
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
			"node=%s", 
			xmlSecErrorsSafeString(xmlSecNodeDSAX));
	    DSA_free(dsa);
	    return(-1);
	}
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
	DSA_free(dsa);
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(dsa->pub_key)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeGetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAY));
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
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
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
    
    if(((xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate) & keyInfoCtx->keyReq.keyType) == 0) {
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
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAP));
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, dsa->p, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeSetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAP));
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
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAQ));
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, dsa->q, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeSetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAQ));
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
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAG));
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, dsa->g, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeSetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAG));
	return(-1);
    }

    /* next is X node: write it ONLY for private keys and ONLY if it is requested */
    if(((keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypePrivate) != 0) && (dsa->priv_key != NULL)) {
	cur = xmlSecAddChild(node, xmlSecNodeDSAX, xmlSecNs);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecAddChild",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s", 
			xmlSecErrorsSafeString(xmlSecNodeDSAX));
	    return(-1);	
	}
	ret = xmlSecOpenSSLNodeSetBNValue(cur, dsa->priv_key, 1);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecOpenSSLNodeSetBNValue",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s", 
			xmlSecErrorsSafeString(xmlSecNodeDSAX));
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
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAY));
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, dsa->pub_key, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeSetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeDSAY));
	return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLKeyDataDsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
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

static xmlSecSize 
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

#endif /* XMLSEC_NO_DSA */

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
							    	 xmlSecSize sizeBits,
								 xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataRsaGetType		(xmlSecKeyDataPtr data);
static xmlSecSize		xmlSecOpenSSLKeyDataRsaGetSize		(xmlSecKeyDataPtr data);
static void		xmlSecOpenSSLKeyDataRsaDebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecOpenSSLKeyDataRsaDebugXmlDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataRsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecOpenSSLEvpKeyDataSize,

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

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecOpenSSLKeyDataRsaGetKlass:
 *
 * The OpenSSL RSA key data klass.
 *
 * Returns pointer to OpenSSL RSA key data klass.
 */
xmlSecKeyDataId 
xmlSecOpenSSLKeyDataRsaGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataRsaKlass);
}

/**
 * xmlSecOpenSSLKeyDataRsaAdoptRsa:
 * @data:		the pointer to RSA key data.
 * @rsa:		the pointer to OpenSSL RSA key.
 *
 * Sets the value of RSA key data.
 *
 * Returns 0 on success or a negative value otherwise.
 */ 
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

/**
 * xmlSecOpenSSLKeyDataRsaGetRsa:
 * @data:		the pointer to RSA key data.
 *
 * Gets the OpenSSL RSA key from RSA key data.
 *
 * Returns pointer to OpenSSL RSA key or NULL if an error occurs.
 */
RSA* 
xmlSecOpenSSLKeyDataRsaGetRsa(xmlSecKeyDataPtr data) {
    EVP_PKEY* pKey;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), NULL);
    
    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(data);
    xmlSecAssert2((pKey == NULL) || (pKey->type == EVP_PKEY_RSA), NULL);
    
    return((pKey != NULL) ? pKey->pkey.rsa : (RSA*)NULL);
}

/** 
 * xmlSecOpenSSLKeyDataRsaAdoptEvp:
 * @data:		the pointer to RSA key data.
 * @pKey:		the pointer to OpenSSL EVP key.
 *
 * Sets the RSA key data value to OpenSSL EVP key.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecOpenSSLKeyDataRsaAdoptEvp(xmlSecKeyDataPtr data, EVP_PKEY* pKey) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2(pKey != NULL, -1);
    xmlSecAssert2(pKey->type == EVP_PKEY_RSA, -1);
    
    return(xmlSecOpenSSLEvpKeyDataAdoptEvp(data, pKey));
}

/**
 * xmlSecOpenSSLKeyDataRsaGetEvp:
 * @data:		the pointer to RSA key data.
 *
 * Gets the OpenSSL EVP key from RSA key data.
 *
 * Returns pointer to OpenSSL EVP key or NULL if an error occurs.
 */
EVP_PKEY* 
xmlSecOpenSSLKeyDataRsaGetEvp(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), NULL);

    return(xmlSecOpenSSLEvpKeyDataGetEvp(data));
}

static int
xmlSecOpenSSLKeyDataRsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);

    return(xmlSecOpenSSLEvpKeyDataInitialize(data));
}

static int
xmlSecOpenSSLKeyDataRsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataRsaId), -1);

    return(xmlSecOpenSSLEvpKeyDataDuplicate(dst, src));
}

static void
xmlSecOpenSSLKeyDataRsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId));

    xmlSecOpenSSLEvpKeyDataFinalize(data);
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
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeRSAModulus));
	RSA_free(rsa);	
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(rsa->n)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeGetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeRSAModulus));
	RSA_free(rsa);
	return(-1);
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
	RSA_free(rsa);
	return(-1);
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &(rsa->e)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeGetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeRSAExponent));
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
			"node=%s", 
			xmlSecErrorsSafeString(xmlSecNodeRSAPrivateExponent));
	    RSA_free(rsa);
	    return(-1);
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
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
    
    if(((xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate) & keyInfoCtx->keyReq.keyType) == 0) {
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
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeRSAModulus));
	return(-1);	
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, rsa->n, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeSetBNValue",
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
    ret = xmlSecOpenSSLNodeSetBNValue(cur, rsa->e, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
		    "xmlSecOpenSSLNodeSetBNValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeRSAExponent));
	return(-1);
    }

    /* next is PrivateExponent node: write it ONLY for private keys and ONLY if it is requested */
    if(((keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypePrivate) != 0) && (rsa->d != NULL)) {
	cur = xmlSecAddChild(node, xmlSecNodeRSAPrivateExponent, xmlSecNs);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecAddChild",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
		        "node=%s", 
			xmlSecErrorsSafeString(xmlSecNodeRSAPrivateExponent));
	    return(-1);	
	}
	ret = xmlSecOpenSSLNodeSetBNValue(cur, rsa->d, 1);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
			"xmlSecOpenSSLNodeSetBNValue",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
		        "node=%s", 
			xmlSecErrorsSafeString(xmlSecNodeRSAPrivateExponent));
	    return(-1);
	}
    }
    
    return(0);
}

static int
xmlSecOpenSSLKeyDataRsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
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
		    "sizeBits=%d", sizeBits);
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

static xmlSecSize 
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
    
#endif /* XMLSEC_NO_RSA */



