/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Private/public (EVP) keys implementation for OpenSSL.
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */
#include "globals.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include "openssl_compat.h"


#ifdef XMLSEC_OPENSSL_API_300
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif /* XMLSEC_OPENSSL_API_300 */

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"

#ifdef OPENSSL_IS_BORINGSSL
#ifndef XMLSEC_NO_RSA
static inline int RSA_test_flags(const RSA *r, int flags) {
    xmlSecAssert2(r != NULL, 0);
    return(r->flags & flags);
}
#endif /* XMLSEC_NO_RSA */

#endif /* OPENSSL_IS_BORINGSSL */


static int
xmlSecOpenSSLGetBNValue(const xmlSecBufferPtr buf, BIGNUM **bigNum) {
    xmlSecByte* bufPtr;
    xmlSecSize bufSize;
    int bufLen;

    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bigNum!= NULL, -1);

    bufPtr = xmlSecBufferGetData(buf);
    bufSize = xmlSecBufferGetSize(buf);
    XMLSEC_SAFE_CAST_SIZE_TO_INT(bufSize, bufLen, return(-1), NULL);

    (*bigNum) = BN_bin2bn(bufPtr, bufLen, (*bigNum));
    if((*bigNum) == NULL) {
        xmlSecOpenSSLError2("BN_bin2bn", NULL, "size=%d", bufLen);
        return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLSetBNValue(const BIGNUM *bigNum, xmlSecBufferPtr buf) {
    xmlSecSize size;
    int ret;

    xmlSecAssert2(bigNum != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    ret = BN_num_bytes(bigNum);
    if(ret < 0) {
        xmlSecOpenSSLError("BN_num_bytes", NULL);
        return(-1);
    }
    XMLSEC_SAFE_CAST_INT_TO_SIZE(ret, size, return(-1), NULL);

    ret = xmlSecBufferSetMaxSize(buf, size + 1);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL,
            "size=" XMLSEC_SIZE_FMT, (size + 1));
        return(-1);
    }

    ret = BN_bn2bin(bigNum, xmlSecBufferGetData(buf));
    if(ret < 0) {
        xmlSecOpenSSLError("BN_bn2bin", NULL);
        return(-1);
    }
    XMLSEC_SAFE_CAST_INT_TO_SIZE(ret, size, return(-1), NULL);

    ret = xmlSecBufferSetSize(buf, size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
                             "size=" XMLSEC_SIZE_FMT, size);
        return(-1);
    }

    return(0);
}

/**************************************************************************
 *
 * Internal OpenSSL EVP key CTX
 *
 *************************************************************************/
typedef struct _xmlSecOpenSSLEvpKeyDataCtx      xmlSecOpenSSLEvpKeyDataCtx,
                                                *xmlSecOpenSSLEvpKeyDataCtxPtr;
struct _xmlSecOpenSSLEvpKeyDataCtx {
    EVP_PKEY*           pKey;
};

/******************************************************************************
 *
 * EVP key data (dsa/rsa)
 *
 *****************************************************************************/
XMLSEC_KEY_DATA_DECLARE(OpenSSLEvpKeyData, xmlSecOpenSSLEvpKeyDataCtx)
#define xmlSecOpenSSLEvpKeyDataSize XMLSEC_KEY_DATA_SIZE(OpenSSLEvpKeyData)

static int              xmlSecOpenSSLEvpKeyDataInitialize       (xmlSecKeyDataPtr data);
static int              xmlSecOpenSSLEvpKeyDataDuplicate        (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
static void             xmlSecOpenSSLEvpKeyDataFinalize         (xmlSecKeyDataPtr data);

/**
 * xmlSecOpenSSLEvpKeyDataAdoptEvp:
 * @data:               the pointer to OpenSSL EVP key data.
 * @pKey:               the pointer to EVP key.
 *
 * Sets the value of key data.
 *
 * Returns: 0 on success or a negative value otherwise.
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
 * @data:               the pointer to OpenSSL EVP data.
 *
 * Gets the EVP_PKEY from the key data.
 *
 * Returns: pointer to EVP_PKEY or NULL if an error occurs.
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
            xmlSecInternalError("xmlSecOpenSSLEvpKeyDup",
                                xmlSecKeyDataGetName(dst));
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
 * @pKey:               the pointer to EVP_PKEY.
 *
 * Duplicates @pKey.
 *
 * Returns: pointer to newly created EVP_PKEY object or NULL if an error occurs.
 */
EVP_PKEY*
xmlSecOpenSSLEvpKeyDup(EVP_PKEY* pKey) {
    int ret;

    xmlSecAssert2(pKey != NULL, NULL);

    ret = EVP_PKEY_up_ref(pKey);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_up_ref", NULL);
        return(NULL);
    }

    return(pKey);
}

/**
 * xmlSecOpenSSLEvpKeyAdopt:
 * @pKey:               the pointer to EVP_PKEY.
 *
 * Creates xmlsec key object from OpenSSL key object.
 *
 * Returns: pointer to newly created xmlsec key or NULL if an error occurs.
 */
xmlSecKeyDataPtr
xmlSecOpenSSLEvpKeyAdopt(EVP_PKEY *pKey) {
    xmlSecKeyDataPtr data = NULL;
    int ret;

    xmlSecAssert2(pKey != NULL, NULL);

    switch(EVP_PKEY_base_id(pKey)) {
#ifndef XMLSEC_NO_RSA
    case EVP_PKEY_RSA:
        data = xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataRsaId);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataRsaId)", NULL);
            return(NULL);
        }
        break;
#endif /* XMLSEC_NO_RSA */
#ifndef XMLSEC_NO_DSA
    case EVP_PKEY_DSA:
        data = xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataDsaId);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataDsaId)", NULL);
            return(NULL);
        }
        break;
#endif /* XMLSEC_NO_DSA */
#ifndef XMLSEC_NO_EC
    case EVP_PKEY_EC:
        data = xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataEcId);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataEcId)", NULL);
            return(NULL);
        }
        break;
#endif /* XMLSEC_NO_EC */

#ifndef XMLSEC_NO_GOST
    case NID_id_GostR3410_2001:
        data = xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataGost2001Id);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataGost2001Id)", NULL);
            return(NULL);
        }
        break;
#endif /* XMLSEC_NO_GOST */

#ifndef XMLSEC_NO_GOST2012
    case NID_id_GostR3410_2012_256:
        data = xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataGostR3410_2012_256Id);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataGostR3410_2012_256Id)", NULL);
            return(NULL);
        }
        break;

    case NID_id_GostR3410_2012_512:
        data = xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataGostR3410_2012_512Id);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataGostR3410_2012_512Id)", NULL);
            return(NULL);
        }
        break;
#endif /* XMLSEC_NO_GOST2012 */

    default:
        xmlSecInvalidIntegerTypeError("evp key type", EVP_PKEY_base_id(pKey),
                "supported evp key type", NULL);
        return(NULL);
    }

    xmlSecAssert2(data != NULL, NULL);
    ret = xmlSecOpenSSLEvpKeyDataAdoptEvp(data, pKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLEvpKeyDataAdoptEvp", NULL);
        xmlSecKeyDataDestroy(data);
        return(NULL);
    }
    pKey = NULL;

    return(data);
}

#ifndef XMLSEC_NO_DSA

/*
 * @xmlSecOpenSSLKeyValueDsa: holds the parts of OpenSSL DSA key
 */
typedef struct _xmlSecOpenSSLKeyValueDsa {
    BIGNUM* p;
    BIGNUM* q;
    BIGNUM* g;
    BIGNUM* pub_key;
    BIGNUM* priv_key;
    int externalPrivKey;
    int notOwner;
} xmlSecOpenSSLKeyValueDsa, *xmlSecOpenSSLKeyValueDsaPtr;

static int
xmlSecOpenSSLKeyValueDsaInitialize(xmlSecOpenSSLKeyValueDsaPtr dsaKeyValue) {
    xmlSecAssert2(dsaKeyValue != NULL, -1);
    memset(dsaKeyValue, 0, sizeof(*dsaKeyValue));
    return(0);
}

static void
xmlSecOpenSSLKeyValueDsaFinalize(xmlSecOpenSSLKeyValueDsaPtr dsaKeyValue) {
    xmlSecAssert(dsaKeyValue != NULL);

    if((dsaKeyValue->notOwner == 0) && (dsaKeyValue->p != NULL)) {
        BN_clear_free(dsaKeyValue->p);
    }
    if((dsaKeyValue->notOwner == 0) && (dsaKeyValue->q != NULL)) {
        BN_clear_free(dsaKeyValue->q);
    }
    if((dsaKeyValue->notOwner == 0) && (dsaKeyValue->g != NULL)) {
        BN_clear_free(dsaKeyValue->g);
    }
    if((dsaKeyValue->notOwner == 0) && (dsaKeyValue->pub_key != NULL)) {
        BN_clear_free(dsaKeyValue->pub_key);
    }
    if((dsaKeyValue->notOwner == 0) && (dsaKeyValue->priv_key != NULL)) {
        BN_clear_free(dsaKeyValue->priv_key);
    }
    memset(dsaKeyValue, 0, sizeof(*dsaKeyValue));
}


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
 *         public)
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

static int              xmlSecOpenSSLKeyDataDsaInitialize       (xmlSecKeyDataPtr data);
static int              xmlSecOpenSSLKeyDataDsaDuplicate        (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
static void             xmlSecOpenSSLKeyDataDsaFinalize         (xmlSecKeyDataPtr data);
static int              xmlSecOpenSSLKeyDataDsaXmlRead          (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecOpenSSLKeyDataDsaXmlWrite         (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecOpenSSLKeyDataDsaGenerate         (xmlSecKeyDataPtr data,
                                                                 xmlSecSize sizeBits,
                                                                 xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataDsaGetType         (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecOpenSSLKeyDataDsaGetSize          (xmlSecKeyDataPtr data);
static void             xmlSecOpenSSLKeyDataDsaDebugDump        (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecOpenSSLKeyDataDsaDebugXmlDump     (xmlSecKeyDataPtr data,
                                                                 FILE* output);

static xmlSecKeyDataPtr xmlSecOpenSSLKeyDataDsaRead             (xmlSecKeyDataId id,
                                                                 xmlSecKeyValueDsaPtr dsaValue);
static int              xmlSecOpenSSLKeyDataDsaWrite            (xmlSecKeyDataId id,
                                                                 xmlSecKeyDataPtr data,
                                                                 xmlSecKeyValueDsaPtr dsaValue,
                                                                 int writePrivateKey);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataDsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecOpenSSLEvpKeyDataSize,

    /* data */
    xmlSecNameDSAKeyValue,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefDSAKeyValue,                      /* const xmlChar* href; */
    xmlSecNodeDSAKeyValue,                      /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecOpenSSLKeyDataDsaInitialize,          /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataDsaDuplicate,           /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataDsaFinalize,            /* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecOpenSSLKeyDataDsaGenerate,            /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecOpenSSLKeyDataDsaGetType,             /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataDsaGetSize,             /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecOpenSSLKeyDataDsaXmlRead,             /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataDsaXmlWrite,            /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataDsaDebugDump,           /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataDsaDebugXmlDump,        /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLKeyDataDsaGetKlass:
 *
 * The DSA key data klass.
 *
 * Returns: pointer to DSA key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataDsaGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataDsaKlass);
}

/**
 * xmlSecOpenSSLKeyDataDsaAdoptEvp:
 * @data:               the pointer to DSA key data.
 * @pKey:               the pointer to OpenSSL EVP key.
 *
 * Sets the DSA key data value to OpenSSL EVP key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLKeyDataDsaAdoptEvp(xmlSecKeyDataPtr data, EVP_PKEY* pKey) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2(pKey != NULL, -1);
    xmlSecAssert2(EVP_PKEY_base_id(pKey) == EVP_PKEY_DSA, -1);

    return(xmlSecOpenSSLEvpKeyDataAdoptEvp(data, pKey));
}

/**
 * xmlSecOpenSSLKeyDataDsaGetEvp:
 * @data:               the pointer to DSA key data.
 *
 * Gets the OpenSSL EVP key from DSA key data.
 *
 * Returns: pointer to OpenSSL EVP key or NULL if an error occurs.
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

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDsaId, -1);
    return(xmlSecKeyDataDsaXmlRead(id, key, node, keyInfoCtx,
        xmlSecOpenSSLKeyDataDsaRead));
}

static int
xmlSecOpenSSLKeyDataDsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDsaId, -1);
    return(xmlSecKeyDataDsaXmlWrite(id, key, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecOpenSSLKeyDataDsaWrite));
}

#ifndef XMLSEC_OPENSSL_API_300

static int
xmlSecOpenSSLKeyDataDsaAdoptDsa(xmlSecKeyDataPtr data, DSA* dsa) {
    EVP_PKEY* pKey = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);

    /* construct new EVP_PKEY */
    if(dsa != NULL) {
        pKey = EVP_PKEY_new();
        if(pKey == NULL) {
            xmlSecOpenSSLError("EVP_PKEY_new",
                               xmlSecKeyDataGetName(data));
            return(-1);
        }
        ret = EVP_PKEY_assign_DSA(pKey, dsa);
        if(ret != 1) {
            xmlSecOpenSSLError("EVP_PKEY_assign_DSA",
                               xmlSecKeyDataGetName(data));
            EVP_PKEY_free(pKey);
            return(-1);
        }
    }

    ret = xmlSecOpenSSLKeyDataDsaAdoptEvp(data, pKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaAdoptEvp",
                            xmlSecKeyDataGetName(data));
        if(pKey != NULL) {
            EVP_PKEY_free(pKey);
        }
        return(-1);
    }
    return(0);
}

static DSA*
xmlSecOpenSSLKeyDataDsaGetDsa(xmlSecKeyDataPtr data) {
    EVP_PKEY* pKey;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), NULL);

    pKey = xmlSecOpenSSLKeyDataDsaGetEvp(data);
    xmlSecAssert2((pKey == NULL) || (EVP_PKEY_base_id(pKey) == EVP_PKEY_DSA), NULL);

    return((pKey != NULL) ? EVP_PKEY_get0_DSA(pKey) : NULL);
}

static int
xmlSecOpenSSLKeyDataDsaGetValue(xmlSecKeyDataPtr data, xmlSecOpenSSLKeyValueDsaPtr dsaKeyValue) {
    DSA* dsa = NULL;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2(dsaKeyValue != NULL, -1);

    /* ensure the values are not getting free'd */
    dsaKeyValue->notOwner =  1;

    dsa = xmlSecOpenSSLKeyDataDsaGetDsa(data);
    if(dsa == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaGetDsa", xmlSecKeyDataGetName(data));
        return(-1);
    }
    DSA_get0_pqg(dsa,
        (const BIGNUM**)&(dsaKeyValue->p),
        (const BIGNUM**)&(dsaKeyValue->q),
        (const BIGNUM**)&(dsaKeyValue->g));
    if((dsaKeyValue->p == NULL) || (dsaKeyValue->q == NULL) || (dsaKeyValue->g == NULL)) {
        xmlSecOpenSSLError("DSA_get0_pqg", xmlSecKeyDataGetName(data));
        return(-1);
    }
    DSA_get0_key(dsa,
        (const BIGNUM**)&(dsaKeyValue->pub_key),
        (const BIGNUM**)&(dsaKeyValue->priv_key));
    if(dsaKeyValue->pub_key == NULL) {
        xmlSecOpenSSLError("DSA_get0_key", xmlSecKeyDataGetName(data));
        return(-1);
    }

    if(dsaKeyValue->priv_key == NULL) {
        /*
        * !!! HACK !!! Also see RSA key
        * We assume here that engine *always* has private key.
        * This might be incorrect but it seems that there is no
        * way to ask engine if given key is private or not.
        */
        const ENGINE* dsa_eng = NULL;
        dsa_eng = DSA_get0_engine(dsa);
        if(dsa_eng != NULL) {
            dsaKeyValue->externalPrivKey = 1;
        } else {
            dsaKeyValue->externalPrivKey = 0;
        }
    }

    /* success */
    return(0);
}


static int
xmlSecOpenSSLKeyDataDsaSetValue(xmlSecKeyDataPtr data, xmlSecOpenSSLKeyValueDsaPtr dsaKeyValue) {
    DSA* dsa = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2(dsaKeyValue != NULL, -1);
    xmlSecAssert2(dsaKeyValue->p != NULL, -1);
    xmlSecAssert2(dsaKeyValue->q != NULL, -1);
    xmlSecAssert2(dsaKeyValue->g != NULL, -1);
    xmlSecAssert2(dsaKeyValue->pub_key != NULL, -1);

    dsa = DSA_new();
    if(dsa == NULL) {
        xmlSecOpenSSLError("DSA_new", xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = DSA_set0_pqg(dsa, dsaKeyValue->p, dsaKeyValue->q, dsaKeyValue->g);
    if(ret != 1) {
        xmlSecOpenSSLError("DSA_set0_pqg", xmlSecKeyDataGetName(data));
        goto done;
    }
    dsaKeyValue->p = NULL;
    dsaKeyValue->q = NULL;
    dsaKeyValue->g = NULL;

    ret = DSA_set0_key(dsa, dsaKeyValue->pub_key, dsaKeyValue->priv_key);
    if(ret != 1) {
        xmlSecOpenSSLError("DSA_set0_key", xmlSecKeyDataGetName(data));
        goto done;
    }
    dsaKeyValue->pub_key = NULL;
    dsaKeyValue->priv_key = NULL;

    ret = xmlSecOpenSSLKeyDataDsaAdoptDsa(data, dsa);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaAdoptDsa",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    dsa = NULL;

    /* success */
    res = 0;

done:
    /* cleanup */
    if(dsa != NULL) {
        DSA_free(dsa);
    }
    return(res);
}

static int
xmlSecOpenSSLKeyDataDsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    DSA* dsa = NULL;
    int counter_ret, bitsLen;
    unsigned long h_ret;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);
    UNREFERENCED_PARAMETER(type);

    dsa = DSA_new();
    if(dsa == NULL) {
        xmlSecOpenSSLError("DSA_new",
                           xmlSecKeyDataGetName(data));
        goto done;
    }

    XMLSEC_SAFE_CAST_SIZE_TO_INT(sizeBits, bitsLen, goto done, NULL);
    ret = DSA_generate_parameters_ex(dsa, bitsLen, NULL, 0, &counter_ret, &h_ret, NULL);
    if(ret != 1) {
        xmlSecOpenSSLError2("DSA_generate_parameters_ex",  xmlSecKeyDataGetName(data),
            "sizeBits=" XMLSEC_SIZE_FMT, sizeBits);
        goto done;
    }

    ret = DSA_generate_key(dsa);
    if(ret < 0) {
        xmlSecOpenSSLError("DSA_generate_key", xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = xmlSecOpenSSLKeyDataDsaAdoptDsa(data, dsa);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaAdoptDsa", xmlSecKeyDataGetName(data));
        goto done;
    }
    dsa = NULL;

    /* success */
    res = 0;

done:
    if(dsa != NULL) {
        DSA_free(dsa);
    }
    return(res);
}

static xmlSecSize
xmlSecOpenSSLKeyDataDsaGetSize(xmlSecKeyDataPtr data) {
    DSA* dsa = NULL;
    const BIGNUM *p = NULL;
    int numBits;
    xmlSecSize res = 0;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), 0);

    dsa = xmlSecOpenSSLKeyDataDsaGetDsa(data);
    if(dsa == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaGetDsa", xmlSecKeyDataGetName(data));
        return(0);
    }

    DSA_get0_pqg(dsa, &p, NULL, NULL);
    if(p == NULL) {
        xmlSecOpenSSLError("DSA_get0_pqg", xmlSecKeyDataGetName(data));
        return(0);
    }
    numBits = BN_num_bits(p);
    if(numBits < 0) {
        xmlSecOpenSSLError("BN_num_bits", xmlSecKeyDataGetName(data));
        return(0);
    }

    XMLSEC_SAFE_CAST_INT_TO_SIZE(numBits, res, return(0), xmlSecKeyDataGetName(data));
    return(res);
}

#else /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLKeyDataDsaGetValue(xmlSecKeyDataPtr data, xmlSecOpenSSLKeyValueDsaPtr dsaKeyValue) {
    const EVP_PKEY* pKey = NULL;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2(dsaKeyValue != NULL, -1);

    pKey = xmlSecOpenSSLKeyDataDsaGetEvp(data);
    xmlSecAssert2(pKey != NULL, -1);

    ret = EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_FFC_P, &(dsaKeyValue->p));
    if((ret != 1) || (dsaKeyValue->p == NULL)) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(p)", xmlSecKeyDataGetName(data));
        return(-1);
    }
    ret = EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_FFC_Q, &(dsaKeyValue->q));
    if((ret != 1) || (dsaKeyValue->q == NULL)) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(q)", xmlSecKeyDataGetName(data));
        return(-1);
    }
    ret = EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_FFC_G, &(dsaKeyValue->g));
    if((ret != 1) || (dsaKeyValue->g == NULL)) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(g)", xmlSecKeyDataGetName(data));
        return(-1);
    }
    ret = EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_PUB_KEY, &(dsaKeyValue->pub_key));
    if((ret != 1) || (dsaKeyValue->pub_key == NULL)) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(pub_key)", xmlSecKeyDataGetName(data));
        return(-1);
    }
    ret = EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_PRIV_KEY, &(dsaKeyValue->priv_key));
    if((ret != 1) || (dsaKeyValue->priv_key == NULL)) {
       /* ignore the error -- public key doesn't have private component */
    }

    /* TODO: implement check for private key on a token (similar to keys on ENGINE) */
    dsaKeyValue->externalPrivKey = 0;

    /* success */
    return(0);
}

static int
xmlSecOpenSSLKeyDataDsaSetValue(xmlSecKeyDataPtr data, xmlSecOpenSSLKeyValueDsaPtr dsaKeyValue) {
    EVP_PKEY* pKey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    OSSL_PARAM_BLD* param_bld = NULL;
    OSSL_PARAM* params = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2(dsaKeyValue != NULL, -1);
    xmlSecAssert2(dsaKeyValue->p != NULL, -1);
    xmlSecAssert2(dsaKeyValue->q != NULL, -1);
    xmlSecAssert2(dsaKeyValue->g != NULL, -1);
    xmlSecAssert2(dsaKeyValue->pub_key != NULL, -1);

    param_bld = OSSL_PARAM_BLD_new();
    if(param_bld == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_new",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_P, dsaKeyValue->p);
    if(ret != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(p)",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_Q, dsaKeyValue->q);
    if(ret != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(q)",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_G, dsaKeyValue->g);
    if(ret != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(g)",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PUB_KEY, dsaKeyValue->pub_key);
    if(ret != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(pub_key)",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, dsaKeyValue->priv_key);
    if(ret != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(priv_key)",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if(params == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_to_param",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ctx = EVP_PKEY_CTX_new_from_name(xmlSecOpenSSLGetLibCtx(), "DSA", NULL);
    if(ctx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_name",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = EVP_PKEY_fromdata_init(ctx);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_fromdata_init",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_fromdata(ctx, &pKey, EVP_PKEY_KEYPAIR, params);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_fromdata",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = xmlSecOpenSSLKeyDataDsaAdoptEvp(data, pKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaAdoptEvp",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    pKey = NULL;

    /* success */
    res = 0;

done:
    if(pKey != NULL) {
        EVP_PKEY_free(pKey);
    }
    if(ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    if(params != NULL) {
        OSSL_PARAM_free(params);
    }
    if(param_bld != NULL) {
        OSSL_PARAM_BLD_free(param_bld);
    }
    return(res);
}

static int
xmlSecOpenSSLKeyDataDsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    EVP_PKEY_CTX* pctx = NULL;
    OSSL_PARAM_BLD* param_bld = NULL;
    OSSL_PARAM* params = NULL;
    EVP_PKEY* pKey = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);
    UNREFERENCED_PARAMETER(type);

    pctx = EVP_PKEY_CTX_new_from_name(xmlSecOpenSSLGetLibCtx(), "DSA", NULL);
    if(pctx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_name", xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_paramgen_init(pctx);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_paramgen_init", xmlSecKeyDataGetName(data));
        goto done;
    }
    param_bld = OSSL_PARAM_BLD_new();
    if(param_bld == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_new", xmlSecKeyDataGetName(data));
        goto done;
    }
    if(OSSL_PARAM_BLD_push_size_t(param_bld, OSSL_PKEY_PARAM_BITS, sizeBits) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_size_t(bits)", xmlSecKeyDataGetName(data));
        goto done;
    }
    params = OSSL_PARAM_BLD_to_param(param_bld);
    if(params == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_to_param", xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_CTX_set_params(pctx, params);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_set_params", xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_generate(pctx, &pKey);
    if(ret <= 0) {
        xmlSecOpenSSLError2("EVP_PKEY_generate", xmlSecKeyDataGetName(data),
            "sizeBits=" XMLSEC_SIZE_FMT, sizeBits);
        goto done;
    }
    ret = xmlSecOpenSSLKeyDataDsaAdoptEvp(data, pKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaAdoptEvp", xmlSecKeyDataGetName(data));
        goto done;
    }
    pKey = NULL;

    /* success */
    res = 0;

done:
    if(pKey != NULL) {
        EVP_PKEY_free(pKey);
    }
    if(params != NULL) {
        OSSL_PARAM_free(params);
    }
    if(param_bld != NULL) {
        OSSL_PARAM_BLD_free(param_bld);
    }
    if(pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }

    return(res);
}

static xmlSecSize
xmlSecOpenSSLKeyDataDsaGetSize(xmlSecKeyDataPtr data) {
    const EVP_PKEY* pKey = NULL;
    BIGNUM *p = NULL;
    int numBits;
    int ret;
    xmlSecSize res = 0;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), 0);

    pKey = xmlSecOpenSSLKeyDataDsaGetEvp(data);
    xmlSecAssert2(pKey != NULL, 0);

    ret = EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_FFC_P, &p);
    if((ret != 1) || (p == NULL)) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(p)", xmlSecKeyDataGetName(data));
        goto done;
    }

    numBits = BN_num_bits(p);
    if(numBits < 0) {
        xmlSecOpenSSLError("BN_num_bits", xmlSecKeyDataGetName(data));
        goto done;
    }

    /* success */
    XMLSEC_SAFE_CAST_INT_TO_SIZE(numBits, res, goto done, xmlSecKeyDataGetName(data));

done:
    /* cleanup */
    if(p != NULL) {
        BN_clear_free(p);
    }
    return(res);
}

#endif /* XMLSEC_OPENSSL_API_300 */

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataDsaGetType(xmlSecKeyDataPtr data) {
    xmlSecOpenSSLKeyValueDsa dsaKeyValue;
    xmlSecKeyDataType res = xmlSecKeyDataTypeUnknown;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), xmlSecKeyDataTypeUnknown);

    ret = xmlSecOpenSSLKeyValueDsaInitialize(&dsaKeyValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyValueDsaInitialize",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = xmlSecOpenSSLKeyDataDsaGetValue(data, &dsaKeyValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaGetValue",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    if((dsaKeyValue.priv_key != NULL) || (dsaKeyValue.externalPrivKey != 0)) {
        res = xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic;
    } else {
        res = xmlSecKeyDataTypePublic;
    }

done:
    xmlSecOpenSSLKeyValueDsaFinalize(&dsaKeyValue);
    return(res);
}

static void
xmlSecOpenSSLKeyDataDsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== dsa key: size = " XMLSEC_SIZE_FMT "\n",
        xmlSecOpenSSLKeyDataDsaGetSize(data));
}

static void
xmlSecOpenSSLKeyDataDsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<DSAKeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
        xmlSecOpenSSLKeyDataDsaGetSize(data));
}

xmlSecKeyDataPtr
xmlSecOpenSSLKeyDataDsaRead(xmlSecKeyDataId id, xmlSecKeyValueDsaPtr dsaValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    xmlSecOpenSSLKeyValueDsa dsaKeyValue;
    int ret;

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDsaId, NULL);
    xmlSecAssert2(dsaValue != NULL, NULL);

    ret = xmlSecOpenSSLKeyValueDsaInitialize(&dsaKeyValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyValueDsaInitialize",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    /*** p ***/
    ret = xmlSecOpenSSLGetBNValue(&(dsaValue->p), &(dsaKeyValue.p));
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLGetBNValue(p)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    /*** q ***/
    ret = xmlSecOpenSSLGetBNValue(&(dsaValue->q), &(dsaKeyValue.q));
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLGetBNValue(q)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    /*** q ***/
    ret = xmlSecOpenSSLGetBNValue(&(dsaValue->g), &(dsaKeyValue.g));
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLGetBNValue(g)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    /*** y ***/
    ret = xmlSecOpenSSLGetBNValue(&(dsaValue->y), &(dsaKeyValue.pub_key));
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLGetBNValue(y)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    /*** x (only for private key) ***/
    if(xmlSecBufferGetSize(&(dsaValue->x)) > 0) {
        /*** p ***/
        ret = xmlSecOpenSSLGetBNValue(&(dsaValue->x), &(dsaKeyValue.priv_key));
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLGetBNValue(x)",
                xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    }

    data = xmlSecKeyDataCreate(id);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecOpenSSLKeyDataDsaSetValue(data, &dsaKeyValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaSetValue()",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* success */
    res = data;
    data = NULL;

done:
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    xmlSecOpenSSLKeyValueDsaFinalize(&dsaKeyValue);
    return(res);
}

static int
xmlSecOpenSSLKeyDataDsaWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data,
                             xmlSecKeyValueDsaPtr dsaValue, int writePrivateKey) {
    xmlSecOpenSSLKeyValueDsa dsaKeyValue;
    int ret;
    int res = -1;

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDsaId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2(dsaValue != NULL, -1);

    /* first, get all values */
    ret = xmlSecOpenSSLKeyValueDsaInitialize(&dsaKeyValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyValueDsaInitialize",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = xmlSecOpenSSLKeyDataDsaGetValue(data, &dsaKeyValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaGetValue",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    /*** p ***/
    xmlSecAssert2(dsaKeyValue.p != NULL, -1);
    ret = xmlSecOpenSSLSetBNValue(dsaKeyValue.p, &(dsaValue->p));
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLSetBNValue(p)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /*** q ***/
    xmlSecAssert2(dsaKeyValue.q != NULL, -1);
    ret = xmlSecOpenSSLSetBNValue(dsaKeyValue.q, &(dsaValue->q));
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLSetBNValue(q)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /*** g ***/
    xmlSecAssert2(dsaKeyValue.g != NULL, -1);
    ret = xmlSecOpenSSLSetBNValue(dsaKeyValue.g, &(dsaValue->g));
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLSetBNValue(g)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /*** y ***/
    xmlSecAssert2(dsaKeyValue.pub_key != NULL, -1);
    ret = xmlSecOpenSSLSetBNValue(dsaKeyValue.pub_key, &(dsaValue->y));
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLSetBNValue(y)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /*** x (only if availabel and requested) ***/
    if((writePrivateKey != 0) && (dsaKeyValue.priv_key != NULL)) {
        ret = xmlSecOpenSSLSetBNValue(dsaKeyValue.priv_key, &(dsaValue->x));
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLSetBNValue(x)",
                xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    }

    /* success */
    res = 0;

done:
    xmlSecOpenSSLKeyValueDsaFinalize(&dsaKeyValue);
    return(res);
}

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_EC
/**************************************************************************
 *
 * EC XML key representation processing.
 *
 * http://csrc.nist.gov/publications/PubsNISTIRs.html#NIST-IR-7802
 *
 * RFC 4050 [RFC4050] describes a possible <dsig:KeyValue> representation
 * for an EC key. The representation and processing instructions
 * described in [RFC4050] are not completely compatible with [XMLDSIG-11];
 * therefore, EC keys SHOULD NOT be provided through a <dsig:KeyValue>
 * element.
 *
 *************************************************************************/

static int              xmlSecOpenSSLKeyDataEcInitialize        (xmlSecKeyDataPtr data);
static int              xmlSecOpenSSLKeyDataEcDuplicate         (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
static void             xmlSecOpenSSLKeyDataEcFinalize          (xmlSecKeyDataPtr data);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataEcGetType          (xmlSecKeyDataPtr data);
static xmlSecSize        xmlSecOpenSSLKeyDataEcGetSize          (xmlSecKeyDataPtr data);

static int              xmlSecOpenSSLKeyDataEcXmlRead           (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecOpenSSLKeyDataEcXmlWrite          (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

static void              xmlSecOpenSSLKeyDataEcDebugDump        (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecOpenSSLKeyDataEcDebugXmlDump      (xmlSecKeyDataPtr data,
                                                                 FILE* output);


static xmlSecKeyDataPtr xmlSecOpenSSLKeyDataEcRead               (xmlSecKeyDataId id,
                                                                  xmlSecKeyValueEcPtr ecValue);
static int              xmlSecOpenSSLKeyDataEcWrite              (xmlSecKeyDataId id,
                                                                 xmlSecKeyDataPtr data,
                                                                 xmlSecKeyValueEcPtr ecValue);


static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataEcKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecOpenSSLEvpKeyDataSize,

    /* data */
    xmlSecNameECKeyValue,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefECKeyValue,                    /* const xmlChar* href; */
    xmlSecNodeECKeyValue,                    /* const xmlChar* dataNodeName; */
    xmlSecDSig11Ns,                           /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecOpenSSLKeyDataEcInitialize,        /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataEcDuplicate,         /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataEcFinalize,          /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecOpenSSLKeyDataEcGetType,           /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataEcGetSize,           /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecOpenSSLKeyDataEcXmlRead,           /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataEcXmlWrite,          /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataEcDebugDump,         /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataEcDebugXmlDump,      /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLKeyDataEcGetKlass:
 *
 * The EC key data klass.
 *
 * Returns: pointer to EC key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataEcGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataEcKlass);
}

/**
 * xmlSecOpenSSLKeyDataEcAdoptEvp:
 * @data:               the pointer to EC key data.
 * @pKey:               the pointer to OpenSSL EVP key.
 *
 * Sets the EC key data value to OpenSSL EVP key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLKeyDataEcAdoptEvp(xmlSecKeyDataPtr data, EVP_PKEY* pKey) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcId), -1);
    xmlSecAssert2(pKey != NULL, -1);
    xmlSecAssert2(EVP_PKEY_base_id(pKey) == EVP_PKEY_EC, -1);
    return(xmlSecOpenSSLEvpKeyDataAdoptEvp(data, pKey));
}

/**
 * xmlSecOpenSSLKeyDataEcGetEvp:
 * @data:               the pointer to EC key data.
 *
 * Gets the OpenSSL EVP key from EC key data.
 *
 * Returns: pointer to OpenSSL EVP key or NULL if an error occurs.
 */
EVP_PKEY*
xmlSecOpenSSLKeyDataEcGetEvp(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcId), NULL);
    return(xmlSecOpenSSLEvpKeyDataGetEvp(data));
}

/**
 * xmlSecOpenSSLKeyDataEcdsaGetKlass:
 *
 * Deprecated. The EC key data klass.
 *
 * Returns: pointer to EC key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataEcdsaGetKlass(void) {
    return(xmlSecOpenSSLKeyDataEcGetKlass());
}

/**
 * xmlSecOpenSSLKeyDataEcdsaAdoptEvp:
 * @data:               the pointer to EC key data.
 * @pKey:               the pointer to OpenSSL EVP key.
 *
 * Deprecated. Sets the EC key data value to OpenSSL EVP key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLKeyDataEcdsaAdoptEvp(xmlSecKeyDataPtr data, EVP_PKEY* pKey) {
    return(xmlSecOpenSSLKeyDataEcAdoptEvp(data, pKey));
}

/**
 * xmlSecOpenSSLKeyDataEcdsaGetEvp:
 * @data:               the pointer to EC key data.
 *
 * Deprecated. Gets the OpenSSL EVP key from EC key data.
 *
 * Returns: pointer to OpenSSL EVP key or NULL if an error occurs.
 */
EVP_PKEY*
xmlSecOpenSSLKeyDataEcdsaGetEvp(xmlSecKeyDataPtr data) {
    return(xmlSecOpenSSLKeyDataEcGetEvp(data));
}



static int
xmlSecOpenSSLKeyDataEcInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcId), -1);

    return(xmlSecOpenSSLEvpKeyDataInitialize(data));
}

static int
xmlSecOpenSSLKeyDataEcDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataEcId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataEcId), -1);

    return(xmlSecOpenSSLEvpKeyDataDuplicate(dst, src));
}

static void
xmlSecOpenSSLKeyDataEcFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcId));

    xmlSecOpenSSLEvpKeyDataFinalize(data);
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataEcGetType(xmlSecKeyDataPtr data ATTRIBUTE_UNUSED) {
    UNREFERENCED_PARAMETER(data);
    /* XXX-MAK: Fix this. */
    return(xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate);
}

typedef struct _xmlSecOpenSSLKeyDataEcCurveNameAndOID {
    int nid;
    xmlChar name[128];
    xmlChar oid[128];
} xmlSecOpenSSLKeyDataEcCurveNameAndOID;

static const xmlSecOpenSSLKeyDataEcCurveNameAndOID g_xmlSecOpenSSLKeyDataEcCurveNameAndOID[] = {
    { NID_X9_62_prime192v1, SN_X9_62_prime192v1, "1.2.840.10045.3.1.1" }, /* "prime192v1" */
    { NID_X9_62_prime192v2, SN_X9_62_prime192v2, "1.2.840.10045.3.1.2" },
    { NID_X9_62_prime192v3, SN_X9_62_prime192v3, "1.2.840.10045.3.1.3" },
    { NID_X9_62_prime239v1, SN_X9_62_prime239v1, "1.2.840.10045.3.1.4" },
    { NID_X9_62_prime239v2, SN_X9_62_prime239v2, "1.2.840.10045.3.1.5" },
    { NID_X9_62_prime239v3, SN_X9_62_prime239v3, "1.2.840.10045.3.1.6" },
    { NID_X9_62_prime256v1, SN_X9_62_prime256v1, "1.2.840.10045.3.1.7" }, /* prime256v1 */
    { NID_secp224r1, SN_secp224r1, "1.3.132.0.33" }, /* secp224r1 */
    { NID_secp384r1, SN_secp384r1, "1.3.132.0.34" }, /* secp384r1 */
    { NID_secp521r1, SN_secp521r1, "1.3.132.0.35" }  /* secp521r1 */
};



#ifndef XMLSEC_OPENSSL_API_300

static const xmlChar*
xmlSecOpenSSLKeyDataEcGetOidFromNid(int nid) {
    xmlSecSize size = sizeof(g_xmlSecOpenSSLKeyDataEcCurveNameAndOID) / sizeof(g_xmlSecOpenSSLKeyDataEcCurveNameAndOID[0]);

    xmlSecAssert2(nid != NID_undef, NULL);

    for(xmlSecSize ii = 0; ii < size; ++ii) {
        if(nid == g_xmlSecOpenSSLKeyDataEcCurveNameAndOID[ii].nid) {
            return(g_xmlSecOpenSSLKeyDataEcCurveNameAndOID[ii].oid);
        }
    }
    return(NULL);
}

static int
xmlSecOpenSSLKeyDataEcGetNidFromOid(const xmlChar * oid) {
    xmlSecSize size = sizeof(g_xmlSecOpenSSLKeyDataEcCurveNameAndOID) / sizeof(g_xmlSecOpenSSLKeyDataEcCurveNameAndOID[0]);

    xmlSecAssert2(oid != NULL, NID_undef);

    for(xmlSecSize ii = 0; ii < size; ++ii) {
        if(xmlStrcmp(oid, g_xmlSecOpenSSLKeyDataEcCurveNameAndOID[ii].oid) == 0) {
            return(g_xmlSecOpenSSLKeyDataEcCurveNameAndOID[ii].nid);
        }
    }
    return(NID_undef);
}

static const EC_KEY*
xmlSecOpenSSLKeyDataEcGetEcKey(xmlSecKeyDataPtr data) {
    EVP_PKEY* pKey;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcId), NULL);

    pKey = xmlSecOpenSSLKeyDataEcGetEvp(data);
    xmlSecAssert2((pKey == NULL) || (EVP_PKEY_base_id(pKey) == EVP_PKEY_EC), NULL);

    return((pKey != NULL) ? EVP_PKEY_get0_EC_KEY(pKey) : NULL);
}

static int
xmlSecOpenSSLKeyDataEcSetEcKey(xmlSecKeyDataPtr data,  EC_KEY* ecKey) {
    EVP_PKEY* pKey;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcId), -1);
    xmlSecAssert2(ecKey != NULL, -1);

    pKey = xmlSecOpenSSLKeyDataEcGetEvp(data);
    xmlSecAssert2(pKey == NULL, -1);

    pKey = EVP_PKEY_new();
    if(pKey == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_new", xmlSecKeyDataGetName(data));
        return(-1);
    }

    ret = EVP_PKEY_set1_EC_KEY(pKey, ecKey);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_PKEY_new", xmlSecKeyDataGetName(data));
        EVP_PKEY_free(pKey);
        return(-1);
    }

    ret = xmlSecOpenSSLKeyDataEcAdoptEvp(data, pKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataEcAdoptEvp", xmlSecKeyDataGetName(data));
        EVP_PKEY_free(pKey);
        return(-1);
    }
    pKey = NULL; /* owned by data */
    return(0);
}


static xmlSecSize
xmlSecOpenSSLKeyDataEcGetSize(xmlSecKeyDataPtr data) {
    const EC_GROUP *group;
    const EC_KEY *ecKey;
    BIGNUM * order = NULL;
    int numBits;
    int ret;
    xmlSecSize res = 0;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcId), 0);

    ecKey = xmlSecOpenSSLKeyDataEcGetEcKey(data);
    if(ecKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataEcGetEcKey", xmlSecKeyDataGetName(data));
        goto done;
    }

    group = EC_KEY_get0_group(ecKey);
    if(group == NULL) {
        xmlSecOpenSSLError("EC_KEY_get0_group", xmlSecKeyDataGetName(data));
        goto done;
    }

    order = BN_new();
    if(order == NULL) {
        xmlSecOpenSSLError("BN_new", xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = EC_GROUP_get_order(group, order, NULL);
    if(ret != 1) {
        xmlSecOpenSSLError("EC_GROUP_get_order", xmlSecKeyDataGetName(data));
        goto done;
    }

    numBits = BN_num_bytes(order);
    if(numBits < 0) {
        xmlSecOpenSSLError("BN_num_bits", xmlSecKeyDataGetName(data));
        goto done;
    }
done:
    if(order != NULL) {
        BN_clear_free(order);
    }
    return(res);
}
static int
xmlSecOpenSSLKeyDataEcWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data, xmlSecKeyValueEcPtr ecValue)
{
    const EC_KEY * ecKey;
    const EC_GROUP * group;
    const EC_POINT * pubkey;
    const xmlChar * curve_oid;
    xmlSecByte * pubkeyData;
    xmlSecSize pubkeySize;
    size_t pubkeyLen;
    int nid;
    int ret;

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataEcId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcId), -1);
    xmlSecAssert2(ecValue != NULL, -1);
    xmlSecAssert2(ecValue->curve == NULL, -1);

    ecKey = xmlSecOpenSSLKeyDataEcGetEcKey(data);
    if(ecKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataEcGetEcKey", xmlSecKeyDataGetName(data));
        return(-1);
    }

    group = EC_KEY_get0_group(ecKey);
    if(group == NULL) {
        xmlSecOpenSSLError("EC_KEY_get0_group", xmlSecKeyDataGetName(data));
        return(-1);
    }

    /* curve oid  */
    nid = EC_GROUP_get_curve_name(group);
    if(nid == NID_undef) {
        xmlSecOpenSSLError("EC_GROUP_get_curve_name", xmlSecKeyDataGetName(data));
        return(-1);
    }
    curve_oid = xmlSecOpenSSLKeyDataEcGetOidFromNid(nid);
    if(curve_oid == NULL) {
        xmlSecInternalError2("xmlSecOpenSSLKeyDataEcGetOidFromNid",  xmlSecKeyDataGetName(data),
            "curve_nid=%d", nid);
        return(-1);
    }
    ecValue->curve = xmlStrdup(curve_oid);
    if(ecValue->curve == NULL) {
        xmlSecStrdupError(curve_oid, xmlSecKeyDataGetName(data));
        return(-1);
    }

    /* public key */
    pubkey = EC_KEY_get0_public_key(ecKey);
    if(pubkey == NULL) {
        xmlSecOpenSSLError("EC_KEY_get0_public_key",  xmlSecKeyDataGetName(data));
        return(-1);
    }

    /* the point is encoded as z||x||y, where z is the octet 0x04  */
    pubkeyLen = EC_POINT_point2oct(group, pubkey, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if(pubkeyLen <= 0) {
        xmlSecOpenSSLError("EC_POINT_point2oct(1)",  xmlSecKeyDataGetName(data));
        return(-1);
    }
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(pubkeyLen, pubkeySize, return(-1), xmlSecKeyDataGetName(data));

    ret = xmlSecBufferSetSize(&(ecValue->pubkey), pubkeySize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "bufSize=" XMLSEC_SIZE_FMT, pubkeySize);
        return (-1);
    }
    pubkeyData = xmlSecBufferGetData(&(ecValue->pubkey));
    xmlSecAssert2(pubkeyData != NULL, -1);

    pubkeyLen = EC_POINT_point2oct(group, pubkey, POINT_CONVERSION_UNCOMPRESSED, pubkeyData, pubkeyLen, NULL);
    if(pubkeyLen <= 0) {
        xmlSecOpenSSLError("EC_POINT_point2oct(2)",  xmlSecKeyDataGetName(data));
        return(-1);
    }

    /* just in case, reset the size again */
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(pubkeyLen, pubkeySize, return(-1), xmlSecKeyDataGetName(data));
    ret = xmlSecBufferSetSize(&(ecValue->pubkey), pubkeySize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "bufSize=" XMLSEC_SIZE_FMT, pubkeySize);
        return (-1);
    }

    /* done */
    return(0);
}

static int
xmlSecOpenSSLKeyDataEcSetValue(xmlSecKeyDataPtr data, const xmlChar* curveOid, xmlSecBufferPtr pubkey) {
    EC_KEY *eckey = NULL;
    EC_GROUP * group = NULL;
    EC_POINT *point = NULL;
    xmlSecByte * pubkeyData;
    xmlSecSize pubkeySize;
    int nid;
    int ret;
    int res = -1;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcId), -1);
    xmlSecAssert2(curveOid != NULL, -1);
    xmlSecAssert2(pubkey != NULL, -1);

    pubkeyData = xmlSecBufferGetData(pubkey);
    pubkeySize = xmlSecBufferGetSize(pubkey);
    xmlSecAssert2(pubkeyData != NULL, -1);
    xmlSecAssert2(pubkeySize > 0, -1);

    /* create group from curve oid */
    nid = xmlSecOpenSSLKeyDataEcGetNidFromOid(curveOid);
    if(nid == NID_undef) {
        xmlSecInternalError2("xmlSecOpenSSLKeyDataEcGetNidFromOid",  xmlSecKeyDataGetName(data),
            "curve_oid=%s", xmlSecErrorsSafeString(curveOid));
        goto done;
    }

    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        xmlSecOpenSSLError2("EC_GROUP_new_by_curve_name",  xmlSecKeyDataGetName(data),
            "nid=%d", nid);
        goto done;
    }

    /* get public key (point) */
    point = EC_POINT_new(group);
    if(point == NULL) {
        xmlSecOpenSSLError("EC_POINT_new",  xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EC_POINT_oct2point(group, point, pubkeyData, pubkeySize, NULL);
    if(ret != 1) {
        xmlSecOpenSSLError("EC_POINT_oct2point",  xmlSecKeyDataGetName(data));
        goto done;
    }

    /* finally create key */
    eckey = EC_KEY_new();
    if(eckey == NULL) {
        xmlSecOpenSSLError("EC_KEY_new",  xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = EC_KEY_set_group(eckey, group);
    if(ret != 1) {
        xmlSecOpenSSLError("EC_KEY_set_group",  xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = EC_KEY_set_public_key(eckey, point);
    if(ret != 1) {
        xmlSecOpenSSLError("EC_KEY_set_public_key",  xmlSecKeyDataGetName(data));
        goto done;
    }

    /* and set in the data */
    ret = xmlSecOpenSSLKeyDataEcSetEcKey(data, eckey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataEcSetEcKey", xmlSecKeyDataGetName(data));
        goto done;
    }

    /* success */
    res = 0;

done:
    if(point != NULL) {
        EC_POINT_free(point);
    }
    if(group != NULL) {
        EC_GROUP_free(group);
    }
    if(eckey!= NULL) {
        EC_KEY_free(eckey);
    }
    return(res);
}
#else /* XMLSEC_OPENSSL_API_300 */

static const xmlChar*
xmlSecOpenSSLKeyDataEcGetOidFromName(const xmlChar* name) {
    xmlSecSize size = sizeof(g_xmlSecOpenSSLKeyDataEcCurveNameAndOID) / sizeof(g_xmlSecOpenSSLKeyDataEcCurveNameAndOID[0]);

    xmlSecAssert2(name != NULL, NULL);

    for(xmlSecSize ii = 0; ii < size; ++ii) {
        if(xmlStrcmp(name, g_xmlSecOpenSSLKeyDataEcCurveNameAndOID[ii].name) == 0) {
            return(g_xmlSecOpenSSLKeyDataEcCurveNameAndOID[ii].oid);
        }
    }
    return(NULL);
}

static const xmlChar*
xmlSecOpenSSLKeyDataEcGetNameFromOid(const xmlChar* oid) {
    xmlSecSize size = sizeof(g_xmlSecOpenSSLKeyDataEcCurveNameAndOID) / sizeof(g_xmlSecOpenSSLKeyDataEcCurveNameAndOID[0]);

    xmlSecAssert2(oid != NULL, NULL);

    for(xmlSecSize ii = 0; ii < size; ++ii) {
        if(xmlStrcmp(oid, g_xmlSecOpenSSLKeyDataEcCurveNameAndOID[ii].oid) == 0) {
            return(g_xmlSecOpenSSLKeyDataEcCurveNameAndOID[ii].name);
        }
    }
    return(NULL);
}

static xmlSecSize
xmlSecOpenSSLKeyDataEcGetSize(xmlSecKeyDataPtr data) {
    const EVP_PKEY* pKey;
    BIGNUM * order = NULL;
    int numBits;
    xmlSecSize res = 0;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcId), 0);

    pKey = xmlSecOpenSSLKeyDataEcGetEvp(data);
    xmlSecAssert2(pKey != NULL, 0);

    ret = EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_EC_ORDER, &order);
    if((ret != 1) || (order == NULL)) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(ec_order)",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    numBits = BN_num_bytes(order);
    if(numBits < 0) {
        xmlSecOpenSSLError("BN_num_bits",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    /* success */
    XMLSEC_SAFE_CAST_INT_TO_SIZE(numBits, res,  goto done, xmlSecKeyDataGetName(data));

done:
    if(order != NULL) {
        BN_clear_free(order);
    }
    return(res);
}

static int
xmlSecOpenSSLKeyDataEcWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data, xmlSecKeyValueEcPtr ecValue)
{

    EVP_PKEY* pKey = NULL;
    const xmlChar* curve_oid;
    char curve_name[128];
    size_t curve_name_len = 0;
    unsigned char *pubkey_data = NULL;
    size_t pubkey_len = 0;
    xmlSecSize pubkey_size;
    int ret;

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataEcId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcId), -1);
    xmlSecAssert2(ecValue != NULL, -1);
    xmlSecAssert2(ecValue->curve == NULL, -1);

    pKey = xmlSecOpenSSLKeyDataEcGetEvp(data);
    xmlSecAssert2(pKey != NULL, -1);

    /* curve name first */
    ret = EVP_PKEY_get_utf8_string_param(pKey, OSSL_PKEY_PARAM_GROUP_NAME,
            curve_name, sizeof(curve_name), &curve_name_len);
    if((ret != 1) || (curve_name_len <= 0) || (curve_name_len >= sizeof(curve_name))) {
        xmlSecOpenSSLError("EVP_PKEY_get_utf8_string_param(GROUP_NAME)", xmlSecKeyDataGetName(data));
        return(-1);
    }
    /* just in case */
    curve_name[curve_name_len] = '\0';
    curve_oid = xmlSecOpenSSLKeyDataEcGetOidFromName(BAD_CAST curve_name);
    if(curve_oid == NULL) {
        xmlSecInternalError2("xmlSecOpenSSLKeyDataEcGetOidFromName",  xmlSecKeyDataGetName(data),
            "curve_name=%s", xmlSecErrorsSafeString(curve_name));
        return(-1);
    }
    ecValue->curve = xmlStrdup(curve_oid);
    if(ecValue->curve == NULL) {
        xmlSecStrdupError(curve_oid, xmlSecKeyDataGetName(data));
        return(-1);
    }

    /* pubkey */
    pubkey_len = EVP_PKEY_get1_encoded_public_key(pKey, &pubkey_data);
    if(pubkey_len == 0) {
        xmlSecOpenSSLError("EVP_PKEY_get1_encoded_public_key", xmlSecKeyDataGetName(data));
        return(-1);
    }
    xmlSecAssert2(pubkey_data != NULL, -1);

    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(pubkey_len, pubkey_size, return(-1), xmlSecKeyDataGetName(data));
    ret = xmlSecBufferSetData(&(ecValue->pubkey), pubkey_data, pubkey_size);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferSetData(pubkey)", xmlSecKeyDataGetName(data));
        OPENSSL_free(pubkey_data);
        return (-1);
    }

    /* done */
    OPENSSL_free(pubkey_data);
    return(0);
}

static int
xmlSecOpenSSLKeyDataEcSetValue(xmlSecKeyDataPtr data, const xmlChar* curveOid, xmlSecBufferPtr pubkey) {
    EVP_PKEY* pKey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    const xmlChar* curve_name;
    xmlSecByte * pubkeyData;
    xmlSecSize pubkeyDataSize;
    int ret;
    int res = -1;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcId), -1);
    xmlSecAssert2(curveOid != NULL, -1);
    xmlSecAssert2(pubkey != NULL, -1);

    pubkeyData = xmlSecBufferGetData(pubkey);
    pubkeyDataSize = xmlSecBufferGetSize(pubkey);
    xmlSecAssert2(pubkeyData != NULL, -1);
    xmlSecAssert2(pubkeyDataSize > 0, -1);

    /* curve name */
    curve_name = xmlSecOpenSSLKeyDataEcGetNameFromOid(curveOid);
    if(curve_name == NULL) {
        xmlSecInternalError2("xmlSecOpenSSLKeyDataEcGetNameFromOid", xmlSecKeyDataGetName(data),
            "curve_oid=%s", xmlSecErrorsSafeString(curveOid));
        goto done;
    }

    /* create pkey ctx */
    ctx = EVP_PKEY_CTX_new_from_name(xmlSecOpenSSLGetLibCtx(), "ec", NULL);
    if(ctx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_name", xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_paramgen_init(ctx);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_PKEY_paramgen_init", xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_CTX_set_group_name(ctx, (const char*)curve_name);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_set_group_name", xmlSecKeyDataGetName(data));
        goto done;
    }

    /* create pkey */
    ret = EVP_PKEY_paramgen(ctx, &pKey);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_PKEY_paramgen", xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_set1_encoded_public_key(pKey, pubkeyData, pubkeyDataSize);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_PKEY_set1_encoded_public_key", xmlSecKeyDataGetName(data));
        goto done;
    }

    /* set pkey into data */
    ret = xmlSecOpenSSLKeyDataEcAdoptEvp(data, pKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataEcAdoptEvp", xmlSecKeyDataGetName(data));
        goto done;
    }
    pKey = NULL;

    /* success */
    res = 0;

done:
    if(pKey != NULL) {
        EVP_PKEY_free(pKey);
    }
    if(ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    return(res);
}

#endif /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLKeyDataEcXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                               xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataEcId, -1);
    return(xmlSecKeyDataEcXmlRead(id, key, node, keyInfoCtx,
        xmlSecOpenSSLKeyDataEcRead));
}

static int
xmlSecOpenSSLKeyDataEcXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataEcId, -1);
    return(xmlSecKeyDataEcXmlWrite(id, key, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecOpenSSLKeyDataEcWrite));
}

static void
xmlSecOpenSSLKeyDataEcDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== ec key: size = " XMLSEC_SIZE_FMT "\n",
        xmlSecOpenSSLKeyDataEcGetSize(data));
}

static void
xmlSecOpenSSLKeyDataEcDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<ECKeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
        xmlSecOpenSSLKeyDataEcGetSize(data));
}


xmlSecKeyDataPtr
xmlSecOpenSSLKeyDataEcRead(xmlSecKeyDataId id, xmlSecKeyValueEcPtr ecValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    int ret;

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataEcId, NULL);
    xmlSecAssert2(ecValue != NULL, NULL);
    xmlSecAssert2(ecValue->curve != NULL, NULL);

    /* create key data */
    data = xmlSecKeyDataCreate(id);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecOpenSSLKeyDataEcSetValue(data, ecValue->curve, &(ecValue->pubkey));
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataEcSetValue()", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* success */
    res = data;
    data = NULL;

done:
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}


#endif /* XMLSEC_NO_EC */

#ifndef XMLSEC_NO_RSA

/*
 * @xmlSecOpenSSLKeyValueRsa: holds the parts of OpenSSL RSA key
 */
typedef struct _xmlSecOpenSSLKeyValueRsa {
    BIGNUM* n;
    BIGNUM* e;
    BIGNUM* d;
    int externalPrivKey;
    int notOwner;
} xmlSecOpenSSLKeyValueRsa, *xmlSecOpenSSLKeyValueRsaPtr;

static int
xmlSecOpenSSLKeyValueRsaInitialize(xmlSecOpenSSLKeyValueRsaPtr rsaKeyValue) {
    xmlSecAssert2(rsaKeyValue != NULL, -1);
    memset(rsaKeyValue, 0, sizeof(*rsaKeyValue));
    return(0);
}

static void
xmlSecOpenSSLKeyValueRsaFinalize(xmlSecOpenSSLKeyValueRsaPtr rsaKeyValue) {
    xmlSecAssert(rsaKeyValue != NULL);

    if((rsaKeyValue->notOwner == 0) && (rsaKeyValue->n != NULL)) {
        BN_clear_free(rsaKeyValue->n);
    }
    if((rsaKeyValue->notOwner == 0) && (rsaKeyValue->e != NULL)) {
        BN_clear_free(rsaKeyValue->e);
    }
    if((rsaKeyValue->notOwner == 0) && (rsaKeyValue->d != NULL)) {
        BN_clear_free(rsaKeyValue->d);
    }
    memset(rsaKeyValue, 0, sizeof(*rsaKeyValue));
}

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
 *        5foK5hhmbktQhyNdy/6LpQRhDUDsTvK+g9Ucj47es9AQJ3U=
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

static int              xmlSecOpenSSLKeyDataRsaInitialize       (xmlSecKeyDataPtr data);
static int              xmlSecOpenSSLKeyDataRsaDuplicate        (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
static void             xmlSecOpenSSLKeyDataRsaFinalize         (xmlSecKeyDataPtr data);
static int              xmlSecOpenSSLKeyDataRsaXmlRead          (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecOpenSSLKeyDataRsaXmlWrite         (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecOpenSSLKeyDataRsaGenerate         (xmlSecKeyDataPtr data,
                                                                 xmlSecSize sizeBits,
                                                                 xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataRsaGetType         (xmlSecKeyDataPtr data);
static xmlSecSize               xmlSecOpenSSLKeyDataRsaGetSize          (xmlSecKeyDataPtr data);
static void             xmlSecOpenSSLKeyDataRsaDebugDump        (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecOpenSSLKeyDataRsaDebugXmlDump     (xmlSecKeyDataPtr data,
                                                                 FILE* output);

static xmlSecKeyDataPtr xmlSecOpenSSLKeyDataRsaRead             (xmlSecKeyDataId id,
                                                                 xmlSecKeyValueRsaPtr rsaValue);
static int              xmlSecOpenSSLKeyDataRsaWrite            (xmlSecKeyDataId id,
                                                                 xmlSecKeyDataPtr data,
                                                                 xmlSecKeyValueRsaPtr rsaValue,
                                                                 int writePrivateKey);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataRsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecOpenSSLEvpKeyDataSize,

    /* data */
    xmlSecNameRSAKeyValue,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefRSAKeyValue,                      /* const xmlChar* href; */
    xmlSecNodeRSAKeyValue,                      /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecOpenSSLKeyDataRsaInitialize,          /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataRsaDuplicate,           /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataRsaFinalize,            /* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecOpenSSLKeyDataRsaGenerate,            /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecOpenSSLKeyDataRsaGetType,             /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataRsaGetSize,             /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecOpenSSLKeyDataRsaXmlRead,             /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataRsaXmlWrite,            /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataRsaDebugDump,           /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataRsaDebugXmlDump,        /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLKeyDataRsaGetKlass:
 *
 * The OpenSSL RSA key data klass.
 *
 * Returns: pointer to OpenSSL RSA key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataRsaGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataRsaKlass);
}



/**
 * xmlSecOpenSSLKeyDataRsaAdoptEvp:
 * @data:               the pointer to RSA key data.
 * @pKey:               the pointer to OpenSSL EVP key.
 *
 * Sets the RSA key data value to OpenSSL EVP key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLKeyDataRsaAdoptEvp(xmlSecKeyDataPtr data, EVP_PKEY* pKey) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2(pKey != NULL, -1);
    xmlSecAssert2(EVP_PKEY_base_id(pKey) == EVP_PKEY_RSA, -1);

    return(xmlSecOpenSSLEvpKeyDataAdoptEvp(data, pKey));
}

/**
 * xmlSecOpenSSLKeyDataRsaGetEvp:
 * @data:               the pointer to RSA key data.
 *
 * Gets the OpenSSL EVP key from RSA key data.
 *
 * Returns: pointer to OpenSSL EVP key or NULL if an error occurs.
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
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataRsaId, -1);
    return(xmlSecKeyDataRsaXmlRead(id, key, node, keyInfoCtx,
        xmlSecOpenSSLKeyDataRsaRead));

}

static int
xmlSecOpenSSLKeyDataRsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                            xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataRsaId, -1);
    return(xmlSecKeyDataRsaXmlWrite(id, key, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecOpenSSLKeyDataRsaWrite));
}

#ifndef XMLSEC_OPENSSL_API_300
static int
xmlSecOpenSSLKeyDataRsaAdoptRsa(xmlSecKeyDataPtr data, RSA* rsa) {
    EVP_PKEY* pKey = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);

    /* construct new EVP_PKEY */
    if(rsa != NULL) {
        pKey = EVP_PKEY_new();
        if(pKey == NULL) {
            xmlSecOpenSSLError("EVP_PKEY_new",
                               xmlSecKeyDataGetName(data));
            return(-1);
        }

        ret = EVP_PKEY_assign_RSA(pKey, rsa);
        if(ret != 1) {
            xmlSecOpenSSLError("EVP_PKEY_assign_RSA",
                               xmlSecKeyDataGetName(data));
            EVP_PKEY_free(pKey);
            return(-1);
        }
    }

    ret = xmlSecOpenSSLKeyDataRsaAdoptEvp(data, pKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataRsaAdoptEvp",
                            xmlSecKeyDataGetName(data));
        if(pKey != NULL) {
            EVP_PKEY_free(pKey);
        }
        return(-1);
    }
    return(0);
}

static RSA*
xmlSecOpenSSLKeyDataRsaGetRsa(xmlSecKeyDataPtr data) {
    EVP_PKEY* pKey;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), NULL);

    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(data);
    xmlSecAssert2((pKey == NULL) || (EVP_PKEY_base_id(pKey) == EVP_PKEY_RSA), NULL);

    return((pKey != NULL) ? EVP_PKEY_get0_RSA(pKey) : NULL);
}

static int
xmlSecOpenSSLKeyDataRsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    RSA* rsa = NULL;
    int lenBits;
    BIGNUM* publicExponent = NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);
    UNREFERENCED_PARAMETER(type);

    /* create publicExponent */
    publicExponent = BN_new();
    if(publicExponent == NULL) {
        xmlSecOpenSSLError("BN_new", xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = BN_set_word(publicExponent, RSA_F4);
    if(ret != 1){
        xmlSecOpenSSLError("BN_set_word", xmlSecKeyDataGetName(data));
        goto done;
    }

    rsa = RSA_new();
    if(rsa == NULL) {
        xmlSecOpenSSLError("RSA_new", xmlSecKeyDataGetName(data));
        goto done;
    }

    XMLSEC_SAFE_CAST_SIZE_TO_INT(sizeBits, lenBits, goto done, NULL);
    ret = RSA_generate_key_ex(rsa, lenBits, publicExponent, NULL);
    if(ret != 1) {
        xmlSecOpenSSLError2("RSA_generate_key_ex", xmlSecKeyDataGetName(data),
            "sizeBits=" XMLSEC_SIZE_FMT, sizeBits);
        goto done;
    }

    ret = xmlSecOpenSSLKeyDataRsaAdoptRsa(data, rsa);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataRsaAdoptRsa", xmlSecKeyDataGetName(data));
        goto done;
    }
    rsa = NULL;


    /* success */
    res = 0;

done:
    if(rsa != NULL) {
        RSA_free(rsa);
    }
    if(publicExponent != NULL) {
        BN_clear_free(publicExponent);
    }
    return(res);
}

static xmlSecSize
xmlSecOpenSSLKeyDataRsaGetSize(xmlSecKeyDataPtr data) {
    RSA* rsa = NULL;
    const BIGNUM* n = NULL;
    int numBits;
    xmlSecSize res;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), 0);

    rsa = xmlSecOpenSSLKeyDataRsaGetRsa(data);
    if(rsa == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataRsaGetRsa", xmlSecKeyDataGetName(data));
        return(0);
    }

    RSA_get0_key(rsa, &n, NULL, NULL);
    if(n == NULL) {
        xmlSecOpenSSLError("RSA_get0_key", xmlSecKeyDataGetName(data));
        return(0);
    }

    numBits = BN_num_bits(n);
    if(numBits < 0) {
        xmlSecOpenSSLError("BN_num_bits", xmlSecKeyDataGetName(data));
        return(0);
    }

    XMLSEC_SAFE_CAST_INT_TO_SIZE(numBits, res, return(0), xmlSecKeyDataGetName(data));
    return(res);
}


static int
xmlSecOpenSSLKeyDataRsaGetValue(xmlSecKeyDataPtr data, xmlSecOpenSSLKeyValueRsaPtr rsaKeyValue) {
    RSA* rsa = NULL;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2(rsaKeyValue != NULL, -1);

    /* ensure the values are not getting free'd */
    rsaKeyValue->notOwner =  1;

    rsa = xmlSecOpenSSLKeyDataRsaGetRsa(data);
    if(rsa == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataRsaGetRsa", xmlSecKeyDataGetName(data));
        return(-1);
    }

    RSA_get0_key(rsa,
        (const BIGNUM**)(&rsaKeyValue->n),
        (const BIGNUM**)(&rsaKeyValue->e),
        (const BIGNUM**)(&rsaKeyValue->d));
    if((rsaKeyValue->n == NULL) || (rsaKeyValue->e == NULL)) {
        xmlSecOpenSSLError("RSA_get0_key", xmlSecKeyDataGetName(data));
        return(-1);
    }

    if(rsaKeyValue->d == NULL) {
        /*
        * !!! HACK !!! Also see DSA key
        * We assume here that engine *always* has private key.
        * This might be incorrect but it seems that there is no
        * way to ask engine if given key is private or not.
        */
        if(RSA_test_flags(rsa, (RSA_FLAG_EXT_PKEY)) != 0) {
            rsaKeyValue->externalPrivKey = 1;
        } else {
            rsaKeyValue->externalPrivKey = 0;
        }
    }

    /* success */
    return(0);
}

static int
xmlSecOpenSSLKeyDataRsaSetValue(xmlSecKeyDataPtr data, xmlSecOpenSSLKeyValueRsaPtr rsaKeyValue) {
    RSA* rsa = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2(rsaKeyValue != NULL, -1);

    rsa = RSA_new();
    if(rsa == NULL) {
        xmlSecOpenSSLError("RSA_new", xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = RSA_set0_key(rsa, rsaKeyValue->n, rsaKeyValue->e, rsaKeyValue->d);
    if(ret == 0) {
        xmlSecOpenSSLError("RSA_set0_key",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    /* owned by rsa now */
    rsaKeyValue->n = NULL;
    rsaKeyValue->e = NULL;
    rsaKeyValue->d = NULL;

    ret = xmlSecOpenSSLKeyDataRsaAdoptRsa(data, rsa);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataRsaAdoptRsa",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    rsa = NULL;

    /* success */
    res = 0;

done:
    if(rsa != NULL) {
        RSA_free(rsa);
    }
    return(res);
}

#else /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLKeyDataRsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    EVP_PKEY_CTX* pctx = NULL;
    OSSL_PARAM_BLD* param_bld = NULL;
    OSSL_PARAM* params = NULL;
    EVP_PKEY* pKey = NULL;
    BIGNUM* publicExponent = NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);
    UNREFERENCED_PARAMETER(type);

    /* create publicExponent */
    publicExponent = BN_new();
    if(publicExponent == NULL) {
        xmlSecOpenSSLError("BN_new",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = BN_set_word(publicExponent, RSA_F4);
    if(ret != 1){
        xmlSecOpenSSLError("BN_set_word",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    pctx = EVP_PKEY_CTX_new_from_name(xmlSecOpenSSLGetLibCtx(), "RSA", NULL);
    if(pctx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_name",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_keygen_init(pctx);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_paramgen_init",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    param_bld = OSSL_PARAM_BLD_new();
    if(param_bld == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_new",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    if(OSSL_PARAM_BLD_push_size_t(param_bld, OSSL_PKEY_PARAM_BITS, sizeBits) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_size_t(bits)",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    if(OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, publicExponent) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(publicExponent)",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if(params == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_to_param",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_CTX_set_params(pctx, params);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_set_param",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_generate(pctx, &pKey);
    if(ret <= 0) {
        xmlSecOpenSSLError2("EVP_PKEY_generate",
            xmlSecKeyDataGetName(data),
            "sizeBits=" XMLSEC_SIZE_FMT, sizeBits);
        goto done;
    }
    ret = xmlSecOpenSSLKeyDataRsaAdoptEvp(data, pKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaAdoptEvp",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    pKey = NULL;

    /* success */
    res = 0;

done:
    if(pKey != NULL) {
        EVP_PKEY_free(pKey);
    }
    if(params != NULL) {
        OSSL_PARAM_free(params);
    }
    if(param_bld != NULL) {
        OSSL_PARAM_BLD_free(param_bld);
    }
    if(pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    if(publicExponent != NULL) {
        BN_clear_free(publicExponent);
    }
    return(res);
}

static xmlSecSize
xmlSecOpenSSLKeyDataRsaGetSize(xmlSecKeyDataPtr data) {
    EVP_PKEY* pKey = NULL;
    BIGNUM* n = NULL;
    int numBits;
    xmlSecSize res = 0;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), 0);

    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(data);
    xmlSecAssert2(pKey != NULL, 0);

    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_N, &n) != 1) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(n)", xmlSecKeyDataGetName(data));
        goto done;
    }

    numBits = BN_num_bits(n);
    if(numBits < 0) {
        xmlSecOpenSSLError("BN_num_bits", xmlSecKeyDataGetName(data));
        goto done;
    }

    /* success */
    XMLSEC_SAFE_CAST_INT_TO_SIZE(numBits, res, goto done, xmlSecKeyDataGetName(data));

done:
    if(n != NULL) {
        BN_clear_free(n);
    }
    return(res);
}

static int
xmlSecOpenSSLKeyDataRsaGetValue(xmlSecKeyDataPtr data, xmlSecOpenSSLKeyValueRsaPtr rsaKeyValue) {
    EVP_PKEY* pKey = NULL;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2(rsaKeyValue != NULL, -1);

    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(data);
    xmlSecAssert2(pKey != NULL, xmlSecKeyDataTypeUnknown);

    ret = EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_N, &(rsaKeyValue->n));
    if((ret != 1) || (rsaKeyValue->n == NULL)) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(n)", xmlSecKeyDataGetName(data));
       return(-1);
    }
    ret = EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_E, &(rsaKeyValue->e));
    if((ret != 1) || (rsaKeyValue->e == NULL)) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(e)", xmlSecKeyDataGetName(data));
       return(-1);
    }
    ret = EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_D, &(rsaKeyValue->d));
    if((ret != 1) || (rsaKeyValue->d == NULL)) {
        /* ignore the error since public keys don't have private component */
    }

    /* TODO: implement check for private key on a token (similar to keys on ENGINE) */
    rsaKeyValue->externalPrivKey = 0;

    /* success */
    return(0);
}

static int
xmlSecOpenSSLKeyDataRsaSetValue(xmlSecKeyDataPtr data, xmlSecOpenSSLKeyValueRsaPtr rsaKeyValue) {
    EVP_PKEY* pKey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    OSSL_PARAM_BLD* param_bld = NULL;
    OSSL_PARAM* params = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2(rsaKeyValue != NULL, -1);

    param_bld = OSSL_PARAM_BLD_new();
    if(param_bld == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_new",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, rsaKeyValue->n);
    if(ret != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(n)",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, rsaKeyValue->e);
    if(ret != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(e)",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_D, rsaKeyValue->d);
    if(ret != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(d)",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if(params == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_to_param",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ctx = EVP_PKEY_CTX_new_from_name(xmlSecOpenSSLGetLibCtx(), "RSA", NULL);
    if(ctx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_name",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = EVP_PKEY_fromdata_init(ctx);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_fromdata_init",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_fromdata(ctx, &pKey, EVP_PKEY_KEYPAIR, params);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_fromdata",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = xmlSecOpenSSLKeyDataRsaAdoptEvp(data, pKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaAdoptEvp",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    pKey = NULL;

    /* success */
    res = 0;

done:
    if(pKey != NULL) {
        EVP_PKEY_free(pKey);
    }
    if(ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    if(params != NULL) {
        OSSL_PARAM_free(params);
    }
    if(param_bld != NULL) {
        OSSL_PARAM_BLD_free(param_bld);
    }
    return(res);
}
#endif /* XMLSEC_OPENSSL_API_300 */

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataRsaGetType(xmlSecKeyDataPtr data) {
    xmlSecOpenSSLKeyValueRsa rsaKeyValue;
    xmlSecKeyDataType res = xmlSecKeyDataTypeUnknown;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), xmlSecKeyDataTypeUnknown);

    ret = xmlSecOpenSSLKeyValueRsaInitialize(&rsaKeyValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyValueRsaInitialize",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = xmlSecOpenSSLKeyDataRsaGetValue(data, &rsaKeyValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataRsaGetValue",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    if((rsaKeyValue.d != NULL) || (rsaKeyValue.externalPrivKey != 0)) {
        res = xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic;
    } else {
        res = xmlSecKeyDataTypePublic;
    }

done:
    xmlSecOpenSSLKeyValueRsaFinalize(&rsaKeyValue);
    return(res);
}


static void
xmlSecOpenSSLKeyDataRsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== rsa key: size = " XMLSEC_SIZE_FMT "\n",
        xmlSecOpenSSLKeyDataRsaGetSize(data));
}

static void
xmlSecOpenSSLKeyDataRsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<RSAKeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
        xmlSecOpenSSLKeyDataRsaGetSize(data));
}

static xmlSecKeyDataPtr
xmlSecOpenSSLKeyDataRsaRead(xmlSecKeyDataId id, xmlSecKeyValueRsaPtr rsaValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    xmlSecOpenSSLKeyValueRsa rsaKeyValue;
    int ret;

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataRsaId, NULL);
    xmlSecAssert2(rsaValue != NULL, NULL);

    ret = xmlSecOpenSSLKeyValueRsaInitialize(&rsaKeyValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyValueRsaInitialize",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /*** Modulus ***/
    ret = xmlSecOpenSSLGetBNValue(&(rsaValue->modulus), &(rsaKeyValue.n));
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLGetBNValue(Modulus)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /*** Exponent ***/
    ret = xmlSecOpenSSLGetBNValue(&(rsaValue->publicExponent), &(rsaKeyValue.e));
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLGetBNValue(Exponent)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    /*** PrivateExponent (only for private key) ***/
    if(xmlSecBufferGetSize(&(rsaValue->privateExponent)) > 0) {
        /*** p ***/
        ret = xmlSecOpenSSLGetBNValue(&(rsaValue->privateExponent), &(rsaKeyValue.d));
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLGetBNValue(x)",
                xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    }

    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
        xmlSecInternalError("xmlSecKeyDataCreate", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecOpenSSLKeyDataRsaSetValue(data, &rsaKeyValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataRsaSetValue()",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* success */
    res = data;
    data = NULL;

done:
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    xmlSecOpenSSLKeyValueRsaFinalize(&rsaKeyValue);
    return(res);
}

static int
xmlSecOpenSSLKeyDataRsaWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data,
                             xmlSecKeyValueRsaPtr rsaValue, int writePrivateKey) {

    xmlSecOpenSSLKeyValueRsa rsaKeyValue;
    int ret;
    int res = -1;

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataRsaId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2(rsaValue != NULL, -1);

    /* first, get all values */
    ret = xmlSecOpenSSLKeyValueRsaInitialize(&rsaKeyValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyValueRsaInitialize",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = xmlSecOpenSSLKeyDataRsaGetValue(data, &rsaKeyValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataRsaGetValue",
            xmlSecKeyDataGetName(data));
        goto done;
    }

    /*** Modulus ***/
    xmlSecAssert2(rsaKeyValue.n != NULL, -1);
    ret = xmlSecOpenSSLSetBNValue(rsaKeyValue.n, &(rsaValue->modulus));
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLSetBNValue(Modulus)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /*** Exponent ***/
    xmlSecAssert2(rsaKeyValue.e != NULL, -1);
    ret = xmlSecOpenSSLSetBNValue(rsaKeyValue.e, &(rsaValue->publicExponent));
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLSetBNValue(Exponent)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /*** PrivateExponent (only if availabel and requested) ***/
    if((writePrivateKey != 0) && (rsaKeyValue.d != NULL)) {
        ret = xmlSecOpenSSLSetBNValue(rsaKeyValue.d, &(rsaValue->privateExponent));
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLSetBNValue(PrivateExponent)",
                xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    }

    /* success */
    res = 0;

done:
    xmlSecOpenSSLKeyValueRsaFinalize(&rsaKeyValue);
    return(res);
}
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_GOST
/**************************************************************************
 *
 * GOST2001 xml key representation processing
 *
 *************************************************************************/
static int              xmlSecOpenSSLKeyDataGost2001Initialize(xmlSecKeyDataPtr data);
static int              xmlSecOpenSSLKeyDataGost2001Duplicate(xmlSecKeyDataPtr dst,
                                                         xmlSecKeyDataPtr src);
static void             xmlSecOpenSSLKeyDataGost2001Finalize(xmlSecKeyDataPtr data);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataGost2001GetType(xmlSecKeyDataPtr data);
static xmlSecSize        xmlSecOpenSSLKeyDataGost2001GetSize(xmlSecKeyDataPtr data);
static void              xmlSecOpenSSLKeyDataGost2001DebugDump(xmlSecKeyDataPtr data,
                                                         FILE* output);
static void             xmlSecOpenSSLKeyDataGost2001DebugXmlDump(xmlSecKeyDataPtr data,
                                                         FILE* output);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataGost2001Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecOpenSSLEvpKeyDataSize,

    /* data */
    xmlSecNameGOST2001KeyValue,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                        /* xmlSecKeyDataUsage usage; */
    xmlSecHrefGOST2001KeyValue,         /* const xmlChar* href; */
    xmlSecNodeGOST2001KeyValue,         /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                       /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecOpenSSLKeyDataGost2001Initialize,    /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataGost2001Duplicate,     /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataGost2001Finalize,      /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL, /* xmlSecOpenSSLKeyDataGost2001Generate,*/   /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecOpenSSLKeyDataGost2001GetType,       /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataGost2001GetSize,       /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                      /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,                                      /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,                                      /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                      /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                      /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataGost2001DebugDump,     /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataGost2001DebugXmlDump,  /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                               /* void* reserved0; */
    NULL,                               /* void* reserved1; */
};

/**
 * xmlSecOpenSSLKeyDataGost2001GetKlass:
 *
 * The GOST2001 key data klass.
 *
 * Returns: pointer to GOST2001 key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataGost2001GetKlass(void) {
    return(&xmlSecOpenSSLKeyDataGost2001Klass);
}


static int
xmlSecOpenSSLKeyDataGost2001Initialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGost2001Id), -1);

    return(xmlSecOpenSSLEvpKeyDataInitialize(data));
}

static int
xmlSecOpenSSLKeyDataGost2001Duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataGost2001Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataGost2001Id), -1);

    return(xmlSecOpenSSLEvpKeyDataDuplicate(dst, src));
}

static void
xmlSecOpenSSLKeyDataGost2001Finalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGost2001Id));

    xmlSecOpenSSLEvpKeyDataFinalize(data);
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataGost2001GetType(xmlSecKeyDataPtr data ATTRIBUTE_UNUSED) {
    UNREFERENCED_PARAMETER(data);

    /* Now I don't know how to find whether we have both private and public key
    or the public only*/
    return(xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate);
}

static xmlSecSize
xmlSecOpenSSLKeyDataGost2001GetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGost2001Id), 0);

    return 512;
}

static void
xmlSecOpenSSLKeyDataGost2001DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGost2001Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== gost key: size = " XMLSEC_SIZE_FMT "\n",
        xmlSecOpenSSLKeyDataGost2001GetSize(data));
}

static void
xmlSecOpenSSLKeyDataGost2001DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGost2001Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<GOST2001KeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
        xmlSecOpenSSLKeyDataGost2001GetSize(data));
}
#endif /* XMLSEC_NO_GOST */

#ifndef XMLSEC_NO_GOST2012

/**************************************************************************
 *
 * GOST R 34.10-2012 256 bit xml key representation processing
 *
 *************************************************************************/
static int              xmlSecOpenSSLKeyDataGostR3410_2012_256Initialize(xmlSecKeyDataPtr data);
static int              xmlSecOpenSSLKeyDataGostR3410_2012_256Duplicate(xmlSecKeyDataPtr dst,
                                                         xmlSecKeyDataPtr src);
static void             xmlSecOpenSSLKeyDataGostR3410_2012_256Finalize(xmlSecKeyDataPtr data);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataGostR3410_2012_256GetType(xmlSecKeyDataPtr data);
static xmlSecSize        xmlSecOpenSSLKeyDataGostR3410_2012_256GetSize(xmlSecKeyDataPtr data);
static void              xmlSecOpenSSLKeyDataGostR3410_2012_256DebugDump(xmlSecKeyDataPtr data,
                                                         FILE* output);
static void             xmlSecOpenSSLKeyDataGostR3410_2012_256DebugXmlDump(xmlSecKeyDataPtr data,
                                                         FILE* output);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataGostR3410_2012_256Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecOpenSSLEvpKeyDataSize,

    /* data */
    xmlSecNameGostR3410_2012_256KeyValue,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                        /* xmlSecKeyDataUsage usage; */
    xmlSecHrefGostR3410_2012_256KeyValue,         /* const xmlChar* href; */
    xmlSecNodeGostR3410_2012_256KeyValue,         /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                       /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecOpenSSLKeyDataGostR3410_2012_256Initialize,    /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataGostR3410_2012_256Duplicate,     /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataGostR3410_2012_256Finalize,      /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL, /* xmlSecOpenSSLKeyDataGostR3410_2012_256Generate,*/   /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecOpenSSLKeyDataGostR3410_2012_256GetType,       /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataGostR3410_2012_256GetSize,       /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                               /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,       /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,       /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                               /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                               /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataGostR3410_2012_256DebugDump,     /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataGostR3410_2012_256DebugXmlDump,/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                               /* void* reserved0; */
    NULL,                               /* void* reserved1; */
};

/**
 * xmlSecOpenSSLKeyDataGostR3410_2012_256GetKlass:
 *
 * The GOST R 34.10-2012 256 bit key data klass.
 *
 * Returns: pointer to GOST R 34.10-2012 256 bit key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataGostR3410_2012_256GetKlass(void) {
    return(&xmlSecOpenSSLKeyDataGostR3410_2012_256Klass);
}


static int
xmlSecOpenSSLKeyDataGostR3410_2012_256Initialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGostR3410_2012_256Id), -1);

    return(xmlSecOpenSSLEvpKeyDataInitialize(data));
}

static int
xmlSecOpenSSLKeyDataGostR3410_2012_256Duplicate(xmlSecKeyDataPtr dst,
xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataGostR3410_2012_256Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataGostR3410_2012_256Id), -1);

    return(xmlSecOpenSSLEvpKeyDataDuplicate(dst, src));
}

static void
xmlSecOpenSSLKeyDataGostR3410_2012_256Finalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGostR3410_2012_256Id));

    xmlSecOpenSSLEvpKeyDataFinalize(data);
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataGostR3410_2012_256GetType(xmlSecKeyDataPtr data ATTRIBUTE_UNUSED) {
    UNREFERENCED_PARAMETER(data);

    /* I don't know how to find whether we have both private and public key
    or the public only*/
    return(xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate);
}

static xmlSecSize
xmlSecOpenSSLKeyDataGostR3410_2012_256GetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGostR3410_2012_256Id), 0);

    return 512;
}

static void
xmlSecOpenSSLKeyDataGostR3410_2012_256DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGostR3410_2012_256Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== gost key: size = " XMLSEC_SIZE_FMT "\n",
        xmlSecOpenSSLKeyDataGostR3410_2012_256GetSize(data));
}

static void
xmlSecOpenSSLKeyDataGostR3410_2012_256DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGostR3410_2012_256Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<GOST2012_256KeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
        xmlSecOpenSSLKeyDataGostR3410_2012_256GetSize(data));
}




/**************************************************************************
 *
 * GOST R 34.10-2012 512 bit xml key representation processing
 *
 *************************************************************************/
static int              xmlSecOpenSSLKeyDataGostR3410_2012_512Initialize(xmlSecKeyDataPtr data);
static int              xmlSecOpenSSLKeyDataGostR3410_2012_512Duplicate(xmlSecKeyDataPtr dst,
                                                         xmlSecKeyDataPtr src);
static void             xmlSecOpenSSLKeyDataGostR3410_2012_512Finalize(xmlSecKeyDataPtr data);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataGostR3410_2012_512GetType(xmlSecKeyDataPtr data);
static xmlSecSize        xmlSecOpenSSLKeyDataGostR3410_2012_512GetSize(xmlSecKeyDataPtr data);
static void              xmlSecOpenSSLKeyDataGostR3410_2012_512DebugDump(xmlSecKeyDataPtr data,
                                                         FILE* output);
static void             xmlSecOpenSSLKeyDataGostR3410_2012_512DebugXmlDump(xmlSecKeyDataPtr data,
                                                         FILE* output);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataGostR3410_2012_512Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecOpenSSLEvpKeyDataSize,

    /* data */
    xmlSecNameGostR3410_2012_512KeyValue,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                        /* xmlSecKeyDataUsage usage; */
    xmlSecHrefGostR3410_2012_512KeyValue,         /* const xmlChar* href; */
    xmlSecNodeGostR3410_2012_512KeyValue,         /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                       /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecOpenSSLKeyDataGostR3410_2012_512Initialize,    /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataGostR3410_2012_512Duplicate,     /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataGostR3410_2012_512Finalize,      /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL, /* xmlSecOpenSSLKeyDataGostR3410_2012_512Generate,*/   /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecOpenSSLKeyDataGostR3410_2012_512GetType,       /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataGostR3410_2012_512GetSize,       /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                               /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,       /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,       /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                               /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                               /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataGostR3410_2012_512DebugDump,     /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataGostR3410_2012_512DebugXmlDump,/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                               /* void* reserved0; */
    NULL,                               /* void* reserved1; */
};

/**
 * xmlSecOpenSSLKeyDataGostR3410_2012_512GetKlass:
 *
 * The GOST R 34.10-2012 512 bit key data klass.
 *
 * Returns: pointer to GOST R 34.10-2012 512 bit key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataGostR3410_2012_512GetKlass(void) {
    return(&xmlSecOpenSSLKeyDataGostR3410_2012_512Klass);
}


static int
xmlSecOpenSSLKeyDataGostR3410_2012_512Initialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGostR3410_2012_512Id), -1);

    return(xmlSecOpenSSLEvpKeyDataInitialize(data));
}

static int
xmlSecOpenSSLKeyDataGostR3410_2012_512Duplicate(xmlSecKeyDataPtr dst,
xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataGostR3410_2012_512Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataGostR3410_2012_512Id), -1);

    return(xmlSecOpenSSLEvpKeyDataDuplicate(dst, src));
}

static void
xmlSecOpenSSLKeyDataGostR3410_2012_512Finalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGostR3410_2012_512Id));

    xmlSecOpenSSLEvpKeyDataFinalize(data);
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataGostR3410_2012_512GetType(xmlSecKeyDataPtr data ATTRIBUTE_UNUSED) {
    UNREFERENCED_PARAMETER(data);

    /* I don't know how to find whether we have both private and public key
    or the public only*/
    return(xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate);
}

static xmlSecSize
xmlSecOpenSSLKeyDataGostR3410_2012_512GetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGostR3410_2012_512Id), 0);

    return 1024;
}

static void
xmlSecOpenSSLKeyDataGostR3410_2012_512DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGostR3410_2012_512Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== gost key: size = " XMLSEC_SIZE_FMT "\n",
            xmlSecOpenSSLKeyDataGostR3410_2012_512GetSize(data));
}

static void
xmlSecOpenSSLKeyDataGostR3410_2012_512DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGostR3410_2012_512Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<GOST2012_512KeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
            xmlSecOpenSSLKeyDataGostR3410_2012_512GetSize(data));
}

#endif /* XMLSEC_NO_GOST2012 */
