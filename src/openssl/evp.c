/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:evp
 * @Short_description: Private/public (EVP) keys implementation for OpenSSL.
 * @Stability: Stable
 *
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
#include <xmlsec/private.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/bn.h>
#include <xmlsec/openssl/evp.h>
#include "openssl_compat.h"


#ifdef XMLSEC_OPENSSL_API_300
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif /* XMLSEC_OPENSSL_API_300 */

#include "../cast_helpers.h"

/******************************************************************************
 *
 * OpenSSL 1.1.0 compatibility
 *
 *****************************************************************************/
#if !defined(XMLSEC_OPENSSL_API_110) && !defined(XMLSEC_OPENSSL_API_300)

#ifndef XMLSEC_NO_RSA

static inline void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d) {
    xmlSecAssert(r != NULL);

    if(n != NULL) {
        (*n) = r->n;
    }
    if(e != NULL) {
        (*e) = r->e;
    }
    if(d != NULL) {
        (*d) = r->d;
    }
}

static inline int RSA_test_flags(const RSA *r, int flags) {
    xmlSecAssert2(r != NULL, 0);
    return(r->flags & flags);
}

static inline int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
    xmlSecAssert2(r != NULL, 0);

    if(((r->n == NULL) && (n == NULL)) || ((r->e == NULL) && (e == NULL))) {
        return(0);
    }
    if(n != NULL) {
        BN_clear_free(r->n);
        r->n = n;
    }
    if(e != NULL) {
        BN_clear_free(r->e);
        r->e = e;
    }
    if(d != NULL) {
        BN_clear_free(r->d);
        r->d = d;
    }
    return(1);
}
#endif /* XMLSEC_NO_RSA */


#ifndef XMLSEC_NO_DSA

static inline void DSA_get0_pqg(const DSA *d, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g) {
    xmlSecAssert(d != NULL);

    if(p != NULL) {
        (*p) = d->p;
    }
    if(q != NULL) {
        (*q) = d->q;
    }
    if(g != NULL) {
        (*g) = d->g;
    }
}

static inline void DSA_get0_key(const DSA *d, const BIGNUM **pub_key, const BIGNUM **priv_key) {
    xmlSecAssert(d != NULL);

    if(pub_key != NULL) {
        (*pub_key) = d->pub_key;
    }
    if(priv_key != NULL) {
        (*priv_key) = d->priv_key;
    }
}

static inline ENGINE *DSA_get0_engine(DSA *d) {
    xmlSecAssert2(d != NULL, NULL);
    return(d->engine);
}

static inline int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
    xmlSecAssert2(d != NULL, 0);

    if(((d->p == NULL) && (p == NULL)) || ((d->q == NULL) && (q == NULL)) || ((d->g == NULL) && (g == NULL))) {
        return(0);
    }

    if(p != NULL) {
        BN_clear_free(d->p);
        d->p = p;
    }
    if(q != NULL) {
        BN_clear_free(d->q);
        d->q = q;
    }
    if(g != NULL) {
        BN_clear_free(d->g);
        d->g = g;
    }
    return(1);
}

static inline int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key) {
    xmlSecAssert2(d != NULL, 0);

    if((d->pub_key == NULL) && (pub_key == NULL)) {
        return(0);
    }

    if(pub_key != NULL) {
        BN_clear_free(d->pub_key);
        d->pub_key = pub_key;
    }
    if(priv_key != NULL) {
        BN_clear_free(d->priv_key);
        d->priv_key = priv_key;
    }
    return(1);
}
#endif /* XMLSEC_NO_DSA */

#endif /* !defined(XMLSEC_OPENSSL_API_110) && !defined(XMLSEC_OPENSSL_API_300) */

#ifdef OPENSSL_IS_BORINGSSL
#ifndef XMLSEC_NO_RSA
static inline int RSA_test_flags(const RSA *r, int flags) {
    xmlSecAssert2(r != NULL, 0);
    return(r->flags & flags);
}
#endif /* XMLSEC_NO_RSA */

#endif /* OPENSSL_IS_BORINGSSL */


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
 * EVP key (dsa/rsa)
 *
 * xmlSecOpenSSLEvpKeyDataCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecOpenSSLEvpKeyDataSize     \
    (sizeof(xmlSecKeyData) + sizeof(xmlSecOpenSSLEvpKeyDataCtx))
#define xmlSecOpenSSLEvpKeyDataGetCtx(data) \
    ((xmlSecOpenSSLEvpKeyDataCtxPtr)(((xmlSecByte*)(data)) + sizeof(xmlSecKeyData)))

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
#ifndef XMLSEC_NO_ECDSA
    case EVP_PKEY_EC:
        data = xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataEcdsaId);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataEcdsaId)", NULL);
            return(NULL);
        }
        break;
#endif /* XMLSEC_NO_ECDSA */

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
static xmlSecSize               xmlSecOpenSSLKeyDataDsaGetSize          (xmlSecKeyDataPtr data);
static void             xmlSecOpenSSLKeyDataDsaDebugDump        (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecOpenSSLKeyDataDsaDebugXmlDump     (xmlSecKeyDataPtr data,
                                                                 FILE* output);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataDsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecOpenSSLEvpKeyDataSize,

    /* data */
    xmlSecNameDSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
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
 * xmlSecOpenSSLKeyDataDsaAdoptDsa:
 * @data:               the pointer to DSA key data.
 * @dsa:                the pointer to OpenSSL DSA key.
 *
 * Sets the value of DSA key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLKeyDataDsaAdoptDsa(xmlSecKeyDataPtr data, DSA* dsa) {
#ifndef XMLSEC_OPENSSL_API_300
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
#else /* XMLSEC_OPENSSL_API_300 */
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(dsa);
    xmlSecNotImplementedError("OpenSSL 3.0 does not support direct access to DSA key");
    return(-1);
#endif /* XMLSEC_OPENSSL_API_300 */
}

/**
 * xmlSecOpenSSLKeyDataDsaGetDsa:
 * @data:               the pointer to DSA key data.
 *
 * Gets the OpenSSL DSA key from DSA key data.
 *
 * Returns: pointer to OpenSSL DSA key or NULL if an error occurs.
 */
DSA*
xmlSecOpenSSLKeyDataDsaGetDsa(xmlSecKeyDataPtr data) {
#ifndef XMLSEC_OPENSSL_API_300
    EVP_PKEY* pKey;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), NULL);

    pKey = xmlSecOpenSSLKeyDataDsaGetEvp(data);
    xmlSecAssert2((pKey == NULL) || (EVP_PKEY_base_id(pKey) == EVP_PKEY_DSA), NULL);

    return((pKey != NULL) ? EVP_PKEY_get0_DSA(pKey) : NULL);
#else /* XMLSEC_OPENSSL_API_300 */
    UNREFERENCED_PARAMETER(data);
    xmlSecNotImplementedError("OpenSSL 3.0 does not support direct access to DSA key");
    return(NULL);
#endif /* XMLSEC_OPENSSL_API_300 */
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
    xmlSecKeyDataPtr data = NULL;
    xmlNodePtr cur;
#ifndef XMLSEC_OPENSSL_API_300
    DSA* dsa = NULL;
#else /* XMLSEC_OPENSSL_API_300 */
    EVP_PKEY* pKey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    OSSL_PARAM_BLD* param_bld = NULL;
    OSSL_PARAM* params = NULL;
#endif /* XMLSEC_OPENSSL_API_300 */
    BIGNUM* p = NULL;
    BIGNUM* q = NULL;
    BIGNUM* g = NULL;
    BIGNUM* priv_key = NULL;
    BIGNUM* pub_key = NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_KEY_DATA,
            xmlSecKeyDataKlassGetName(id),
            "Key data value is already set");
        goto done;
    }

    cur = xmlSecGetNextElementNode(node->children);

    /* first is P node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAP, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAP, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    if(xmlSecOpenSSLNodeGetBNValue(cur, &p) == NULL) {
        xmlSecInternalError2("xmlSecOpenSSLNodeGetBNValue",
            xmlSecKeyDataKlassGetName(id),
            "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAP));
        goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is Q node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAQ, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAQ, xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &q) == NULL) {
        xmlSecInternalError2("xmlSecOpenSSLNodeGetBNValue",
            xmlSecKeyDataKlassGetName(id),
            "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAQ));
        goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is G node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAG, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAG, xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &g) == NULL) {
        xmlSecInternalError2("xmlSecOpenSSLNodeGetBNValue",
            xmlSecKeyDataKlassGetName(id),
            "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAG));
        goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAX, xmlSecNs))) {
        /* next is X node. It is REQUIRED for private key but
         * we are not sure exactly what do we read */
        if(xmlSecOpenSSLNodeGetBNValue(cur, &priv_key) == NULL) {
            xmlSecInternalError2("xmlSecOpenSSLNodeGetBNValue",
                xmlSecKeyDataKlassGetName(id),
                "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAX));
            goto done;
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next is Y node. */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAY, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAY, xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &pub_key) == NULL) {
        xmlSecInternalError2("xmlSecOpenSSLNodeGetBNValue",
            xmlSecKeyDataKlassGetName(id),
            "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAY));
        goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* todo: add support for J */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAJ, xmlSecDSigNs))) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* todo: add support for seed */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSASeed, xmlSecDSigNs))) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* todo: add support for pgencounter */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAPgenCounter, xmlSecDSigNs))) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    data = xmlSecKeyDataCreate(id);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

#ifndef XMLSEC_OPENSSL_API_300
    dsa = DSA_new();
    if(dsa == NULL) {
        xmlSecOpenSSLError("DSA_new", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = DSA_set0_pqg(dsa, p, q, g);
    if(ret != 1) {
        xmlSecOpenSSLError("DSA_set0_pqg", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    p = NULL;
    q = NULL;
    g = NULL;

    ret = DSA_set0_key(dsa, pub_key, priv_key);
    if(ret != 1) {
        xmlSecOpenSSLError("DSA_set0_key", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    pub_key = NULL;
    priv_key = NULL;

    ret = xmlSecOpenSSLKeyDataDsaAdoptDsa(data, dsa);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaAdoptDsa", xmlSecKeyDataGetName(data));
        goto done;
    }
    dsa = NULL;

#else /* XMLSEC_OPENSSL_API_300 */
    param_bld = OSSL_PARAM_BLD_new();
    if(param_bld == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_new", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_P, p) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(p)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_Q, q) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(q)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_G, g) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(g)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PUB_KEY, pub_key) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(pub_key)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_key) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(priv_key)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if(params == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_to_param", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ctx = EVP_PKEY_CTX_new_from_name(xmlSecOpenSSLGetLibCtx(), "DSA", NULL);
    if(ctx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_name", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = EVP_PKEY_fromdata_init(ctx);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_fromdata_init", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = EVP_PKEY_fromdata(ctx, &pKey, EVP_PKEY_KEYPAIR, params);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_fromdata", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = xmlSecOpenSSLKeyDataDsaAdoptEvp(data, pKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaAdoptEvp", xmlSecKeyDataGetName(data));
        goto done;
    }
    pKey = NULL;
#endif /* XMLSEC_OPENSSL_API_300 */

    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", xmlSecKeyDataGetName(data));
        goto done;
    }
    data = NULL;

    /* success */
    res = 0;

done:
#ifndef XMLSEC_OPENSSL_API_300
    if(dsa != NULL) {
        DSA_free(dsa);
    }
#else /* XMLSEC_OPENSSL_API_300 */
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
#endif /* XMLSEC_OPENSSL_API_300 */
    if(p != NULL) {
        BN_clear_free(p);
    }
    if(q != NULL) {
        BN_clear_free(q);
    }
    if(g != NULL) {
        BN_clear_free(g);
    }
    if(priv_key != NULL) {
        BN_clear_free(priv_key);
    }
    if(pub_key != NULL) {
        BN_clear_free(pub_key);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

static int
xmlSecOpenSSLKeyDataDsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlNodePtr cur;
#ifndef XMLSEC_OPENSSL_API_300
    DSA* dsa = NULL;
    const BIGNUM* p = NULL;
    const BIGNUM* q = NULL;
    const BIGNUM* g = NULL;
    const BIGNUM* priv_key = NULL;
    const BIGNUM* pub_key = NULL;
#else /* XMLSEC_OPENSSL_API_300 */
    const EVP_PKEY* pKey = NULL;
    BIGNUM* p = NULL;
    BIGNUM* q = NULL;
    BIGNUM* g = NULL;
    BIGNUM* priv_key = NULL;
    BIGNUM* pub_key = NULL;
#endif /* XMLSEC_OPENSSL_API_300 */
    int ret;
    int res = -1;

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(((xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate) & keyInfoCtx->keyReq.keyType) == 0) {
        /* we can have only private key or public key */
        goto done;
    }

    /* first, get all values */
#ifndef XMLSEC_OPENSSL_API_300
    dsa = xmlSecOpenSSLKeyDataDsaGetDsa(xmlSecKeyGetValue(key));
    xmlSecAssert2(dsa != NULL, -1);

    DSA_get0_pqg(dsa, &p, &q, &g);
    DSA_get0_key(dsa, &pub_key, &priv_key);
#else /* XMLSEC_OPENSSL_API_300 */
    pKey = xmlSecOpenSSLKeyDataDsaGetEvp(xmlSecKeyGetValue(key));
    xmlSecAssert2(pKey != NULL, -1);

    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_FFC_P, &p) != 1) {
       xmlSecOpenSSLError("EVP_PKEY_get_bn_param(p)", xmlSecKeyDataKlassGetName(id));
       goto done;
    }
    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_FFC_Q, &q) != 1) {
       xmlSecOpenSSLError("EVP_PKEY_get_bn_param(q)", xmlSecKeyDataKlassGetName(id));
       goto done;
    }
    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_FFC_G, &g) != 1) {
       xmlSecOpenSSLError("EVP_PKEY_get_bn_param(g)", xmlSecKeyDataKlassGetName(id));
       goto done;
    }
    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_PUB_KEY, &pub_key) != 1) {
       xmlSecOpenSSLError("EVP_PKEY_get_bn_param(pub_key)", xmlSecKeyDataKlassGetName(id));
       goto done;
    }
    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_key) != 1) {
       /* ignore the error -- public key doesn't have private component */
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    /* first is P node */
    xmlSecAssert2(p != NULL, -1);
    cur = xmlSecAddChild(node, xmlSecNodeDSAP, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError2("xmlSecAddChild",
                             xmlSecKeyDataKlassGetName(id),
                            "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAP));
        goto done;
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, p, 1);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecOpenSSLNodeSetBNValue",
                             xmlSecKeyDataKlassGetName(id),
                             "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAP));
        goto done;
    }

    /* next is Q node. */
    xmlSecAssert2(q != NULL, -1);
    cur = xmlSecAddChild(node, xmlSecNodeDSAQ, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError2("xmlSecAddChild",
                             xmlSecKeyDataKlassGetName(id),
                             "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAQ));
        goto done;
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, q, 1);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecOpenSSLNodeSetBNValue",
                             xmlSecKeyDataKlassGetName(id),
                             "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAQ));
        goto done;
    }

    /* next is G node. */
    xmlSecAssert2(g != NULL, -1);
    cur = xmlSecAddChild(node, xmlSecNodeDSAG, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError2("xmlSecAddChild",
                             xmlSecKeyDataKlassGetName(id),
                             "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAG));
        goto done;
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, g, 1);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecOpenSSLNodeSetBNValue",
                             xmlSecKeyDataKlassGetName(id),
                             "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAG));
        goto done;
    }

    /* next is X node: write it ONLY for private keys and ONLY if it is requested */
    if(((keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypePrivate) != 0) && (priv_key != NULL)) {
        cur = xmlSecAddChild(node, xmlSecNodeDSAX, xmlSecNs);
        if(cur == NULL) {
            xmlSecInternalError2("xmlSecAddChild",
                                 xmlSecKeyDataKlassGetName(id),
                                 "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAX));
            goto done;
        }
        ret = xmlSecOpenSSLNodeSetBNValue(cur, priv_key, 1);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecOpenSSLNodeSetBNValue",
                                 xmlSecKeyDataKlassGetName(id),
                                  "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAX));
            goto done;
        }
    }

    /* next is Y node. */
    xmlSecAssert2(pub_key != NULL, -1);
    cur = xmlSecAddChild(node, xmlSecNodeDSAY, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError2("xmlSecAddChild",
                             xmlSecKeyDataKlassGetName(id),
                             "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAY));
        goto done;
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, pub_key, 1);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecOpenSSLNodeSetBNValue",
                             xmlSecKeyDataKlassGetName(id),
                             "node=%s", xmlSecErrorsSafeString(xmlSecNodeDSAY));
        goto done;
    }

    /* success */
    res = 0;

done:
#ifdef XMLSEC_OPENSSL_API_300
    if(p != NULL) {
        BN_clear_free(p);
    }
    if(q != NULL) {
        BN_clear_free(q);
    }
    if(g != NULL) {
        BN_clear_free(g);
    }
    if(priv_key != NULL) {
        BN_clear_free(priv_key);
    }
    if(pub_key != NULL) {
        BN_clear_free(pub_key);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    return(res);
}

static int
xmlSecOpenSSLKeyDataDsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
#ifndef XMLSEC_OPENSSL_API_300
    DSA* dsa = NULL;
    int counter_ret;
    unsigned long h_ret;
#else /* XMLSEC_OPENSSL_API_300 */
    EVP_PKEY_CTX* pctx = NULL;
    OSSL_PARAM_BLD* param_bld = NULL;
    OSSL_PARAM* params = NULL;
    EVP_PKEY* pKey = NULL;
#endif /* XMLSEC_OPENSSL_API_300 */
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);
    UNREFERENCED_PARAMETER(type);

#ifndef XMLSEC_OPENSSL_API_300
    dsa = DSA_new();
    if(dsa == NULL) {
        xmlSecOpenSSLError("DSA_new",
                           xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = DSA_generate_parameters_ex(dsa, sizeBits, NULL, 0, &counter_ret, &h_ret, NULL);
    if(ret != 1) {
        xmlSecOpenSSLError2("DSA_generate_parameters_ex",
                            xmlSecKeyDataGetName(data),
                            "sizeBits=%lu", XMLSEC_UL_BAD_CAST(sizeBits));
        goto done;
    }

    ret = DSA_generate_key(dsa);
    if(ret < 0) {
        xmlSecOpenSSLError("DSA_generate_key",
                           xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = xmlSecOpenSSLKeyDataDsaAdoptDsa(data, dsa);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaAdoptDsa",
                            xmlSecKeyDataGetName(data));
        goto done;
    }
    dsa = NULL;

#else /* XMLSEC_OPENSSL_API_300 */
    pctx = EVP_PKEY_CTX_new_from_name(xmlSecOpenSSLGetLibCtx(), "DSA", NULL);
    if(pctx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_name",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_paramgen_init(pctx);
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
#ifndef XMLSEC_NO_SIZE_T
    if(OSSL_PARAM_BLD_push_size_t(param_bld, OSSL_PKEY_PARAM_BITS, sizeBits) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_size_t(bits)",
            xmlSecKeyDataGetName(data));
        goto done;
    }
#else /* XMLSEC_NO_SIZE_T */
    if(OSSL_PARAM_BLD_push_uint(param_bld, OSSL_PKEY_PARAM_BITS, sizeBits) != 1) {
       xmlSecOpenSSLError("OSSL_PARAM_BLD_push_uint(bits)",
            xmlSecKeyDataGetName(data));
        goto done;
    }
#endif /* XMLSEC_NO_SIZE_T */
    params = OSSL_PARAM_BLD_to_param(param_bld);
    if(params == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_to_param",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_CTX_set_params(pctx, params);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_set_params",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_generate(pctx, &pKey);
    if(ret <= 0) {
        xmlSecOpenSSLError2("EVP_PKEY_generate",
            xmlSecKeyDataGetName(data),
            "sizeBits=%lu", XMLSEC_UL_BAD_CAST(sizeBits));
        goto done;
    }
    ret = xmlSecOpenSSLKeyDataDsaAdoptEvp(data, pKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaAdoptEvp",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    pKey = NULL;
#endif /* XMLSEC_OPENSSL_API_300 */

    /* success */
    res = 0;

done:
#ifndef XMLSEC_OPENSSL_API_300
    if(dsa != NULL) {
        DSA_free(dsa);
    }
#else /* XMLSEC_OPENSSL_API_300 */
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
#endif /* XMLSEC_OPENSSL_API_300 */

    return(res);
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataDsaGetType(xmlSecKeyDataPtr data) {
#ifndef XMLSEC_OPENSSL_API_300
    DSA* dsa = NULL;
    const ENGINE* dsa_eng = NULL;
    const BIGNUM* p = NULL;
    const BIGNUM* q = NULL;
    const BIGNUM* g = NULL;
    const BIGNUM* priv_key = NULL;
    const BIGNUM* pub_key = NULL;
#else /* XMLSEC_OPENSSL_API_300 */
    const EVP_PKEY* pKey = NULL;
    BIGNUM* p = NULL;
    BIGNUM* q = NULL;
    BIGNUM* g = NULL;
    BIGNUM* priv_key = NULL;
    BIGNUM* pub_key = NULL;
#endif /* XMLSEC_OPENSSL_API_300 */
    xmlSecKeyDataType res = xmlSecKeyDataTypeUnknown;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), xmlSecKeyDataTypeUnknown);

#ifndef XMLSEC_OPENSSL_API_300
    dsa = xmlSecOpenSSLKeyDataDsaGetDsa(data);
    if(dsa == NULL) {
        goto done;
    }

    DSA_get0_pqg(dsa, &p, &q, &g);
    DSA_get0_key(dsa, &pub_key, &priv_key);
    dsa_eng = DSA_get0_engine(dsa);

    if(p != NULL && q != NULL && g != NULL && pub_key != NULL) {
        if(priv_key != NULL) {
            res = xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic;
        } else if(dsa_eng != NULL) {
            /*
             * !!! HACK !!! Also see RSA key
             * We assume here that engine *always* has private key.
             * This might be incorrect but it seems that there is no
             * way to ask engine if given key is private or not.
             */
            res = xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic;
        } else {
            res = xmlSecKeyDataTypePublic;
        }
    }
#else /* XMLSEC_OPENSSL_API_300 */
    pKey = xmlSecOpenSSLKeyDataDsaGetEvp(data);
    xmlSecAssert2(pKey != NULL, xmlSecKeyDataTypeUnknown);

    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_FFC_P, &p) != 1) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(p)", xmlSecKeyDataGetName(data));
        goto done;
    }
    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_FFC_Q, &q) != 1) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(q)", xmlSecKeyDataGetName(data));
        goto done;
    }
    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_FFC_G, &g) != 1) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(g)", xmlSecKeyDataGetName(data));
        goto done;
    }
    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_PUB_KEY, &pub_key) != 1) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(pub_key)", xmlSecKeyDataGetName(data));
        goto done;
    }
    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_key) != 1) {
       /* ignore the error -- public key doesn't have private component */
    }

    if(p != NULL && q != NULL && g != NULL && pub_key != NULL) {
        if(priv_key != NULL) {
            res = xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic;
        } else {
            res = xmlSecKeyDataTypePublic;
        }
    }
#endif /* XMLSEC_OPENSSL_API_300 */

done:
#ifdef XMLSEC_OPENSSL_API_300
    if(p != NULL) {
        BN_clear_free(p);
    }
    if(q != NULL) {
        BN_clear_free(q);
    }
    if(g != NULL) {
        BN_clear_free(g);
    }
    if(priv_key != NULL) {
        BN_clear_free(priv_key);
    }
    if(pub_key != NULL) {
        BN_clear_free(pub_key);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    return(res);
}

static xmlSecSize
xmlSecOpenSSLKeyDataDsaGetSize(xmlSecKeyDataPtr data) {
#ifndef XMLSEC_OPENSSL_API_300
    DSA* dsa = NULL;
    const BIGNUM *p = NULL;
#else /* XMLSEC_OPENSSL_API_300 */
    const EVP_PKEY* pKey = NULL;
    BIGNUM *p = NULL;
#endif /* XMLSEC_OPENSSL_API_300 */
    int numBits;
    xmlSecSize res = 0;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId), 0);

#ifndef XMLSEC_OPENSSL_API_300
    dsa = xmlSecOpenSSLKeyDataDsaGetDsa(data);
    if(dsa == NULL) {
        return(0);
    }

    DSA_get0_pqg(dsa, &p, NULL, NULL);
    if(p == NULL) {
        return(0);
    }
    numBits = BN_num_bits(p);
#else /* XMLSEC_OPENSSL_API_300 */
    pKey = xmlSecOpenSSLKeyDataDsaGetEvp(data);
    xmlSecAssert2(pKey != NULL, 0);

    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_FFC_P, &p) != 1) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(p)", xmlSecKeyDataGetName(data));
        return(0);
    }
    if(p == NULL) {
        return(0);
    } 
    numBits = BN_num_bits(p);
    BN_clear_free(p);
#endif /* XMLSEC_OPENSSL_API_300 */

    if(numBits < 0) {
        xmlSecOpenSSLError("BN_num_bits", xmlSecKeyDataGetName(data));
        return(0);
    }

    XMLSEC_SAFE_CAST_INT_TO_SIZE(numBits, res, return(0), xmlSecKeyDataGetName(data));
    return(res);
}

static void
xmlSecOpenSSLKeyDataDsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== dsa key: size = %lu\n",
            XMLSEC_UL_BAD_CAST(xmlSecOpenSSLKeyDataDsaGetSize(data)));
}

static void
xmlSecOpenSSLKeyDataDsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<DSAKeyValue size=\"%lu\" />\n",
            XMLSEC_UL_BAD_CAST(xmlSecOpenSSLKeyDataDsaGetSize(data)));
}
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_ECDSA
/**************************************************************************
 *
 * ECDSA XML key representation processing.
 *
 * http://csrc.nist.gov/publications/PubsNISTIRs.html#NIST-IR-7802
 *
 * RFC 4050 [RFC4050] describes a possible <dsig:KeyValue> representation
 * for an ECDSA key. The representation and processing instructions
 * described in [RFC4050] are not completely compatible with [XMLDSIG-11];
 * therefore, ECDSA keys SHOULD NOT be provided through a <dsig:KeyValue>
 * element.
 *
 *************************************************************************/
static int              xmlSecOpenSSLKeyDataEcdsaInitialize(xmlSecKeyDataPtr data);
static int              xmlSecOpenSSLKeyDataEcdsaDuplicate(xmlSecKeyDataPtr dst,
                                                           xmlSecKeyDataPtr src);
static void             xmlSecOpenSSLKeyDataEcdsaFinalize(xmlSecKeyDataPtr data);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataEcdsaGetType(xmlSecKeyDataPtr data);
static xmlSecSize        xmlSecOpenSSLKeyDataEcdsaGetSize(xmlSecKeyDataPtr data);
static void              xmlSecOpenSSLKeyDataEcdsaDebugDump(xmlSecKeyDataPtr data,
                                                         FILE* output);
static void             xmlSecOpenSSLKeyDataEcdsaDebugXmlDump(xmlSecKeyDataPtr data,
                                                         FILE* output);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataEcdsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecOpenSSLEvpKeyDataSize,

    /* data */
    xmlSecNameECDSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefECDSAKeyValue,                    /* const xmlChar* href; */
    xmlSecNodeECDSAKeyValue,                    /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecOpenSSLKeyDataEcdsaInitialize,        /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataEcdsaDuplicate,         /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataEcdsaFinalize,          /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecOpenSSLKeyDataEcdsaGetType,           /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataEcdsaGetSize,           /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,                                       /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,                                       /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataEcdsaDebugDump,         /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataEcdsaDebugXmlDump,      /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLKeyDataEcdsaGetKlass:
 *
 * The ECDSA key data klass.
 *
 * Returns: pointer to ECDSA key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataEcdsaGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataEcdsaKlass);
}

/**
 * xmlSecOpenSSLKeyDataEcdsaAdoptEcdsa:
 * @data:               the pointer to ECDSA key data.
 * @ecdsa:              the pointer to OpenSSL ECDSA key.
 *
 * Sets the value of ECDSA key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLKeyDataEcdsaAdoptEcdsa(xmlSecKeyDataPtr data, EC_KEY* ecdsa) {
#ifndef XMLSEC_OPENSSL_API_300
    EVP_PKEY* pKey = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcdsaId), -1);

    /* construct new EVP_PKEY */
    if(ecdsa != NULL) {
        pKey = EVP_PKEY_new();
        if(pKey == NULL) {
            xmlSecOpenSSLError("EVP_PKEY_new",
                               xmlSecKeyDataGetName(data));
            return(-1);
        }

        ret = EVP_PKEY_assign_EC_KEY(pKey, ecdsa);
        if(ret != 1) {
            xmlSecOpenSSLError("EVP_PKEY_assign_EC_KEY",
                               xmlSecKeyDataGetName(data));
            EVP_PKEY_free(pKey);
            return(-1);
        }
    }

    ret = xmlSecOpenSSLKeyDataEcdsaAdoptEvp(data, pKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataEcdsaAdoptEvp",
                            xmlSecKeyDataGetName(data));
        if(pKey != NULL) {
            EVP_PKEY_free(pKey);
        }
        return(-1);
    }
    return(0);
#else /* XMLSEC_OPENSSL_API_300 */
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(ecdsa);
    xmlSecNotImplementedError("OpenSSL 3.0 does not support direct access to ECDSA key");
    return(-1);
#endif /* XMLSEC_OPENSSL_API_300 */
}

/**
 * xmlSecOpenSSLKeyDataEcdsaGetEcdsa:
 * @data:               the pointer to ECDSA key data.
 *
 * Gets the OpenSSL ECDSA key from ECDSA key data.
 *
 * Returns: pointer to OpenSSL ECDSA key or NULL if an error occurs.
 */
EC_KEY*
xmlSecOpenSSLKeyDataEcdsaGetEcdsa(xmlSecKeyDataPtr data) {
#ifndef XMLSEC_OPENSSL_API_300
    EVP_PKEY* pKey;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcdsaId), NULL);

    pKey = xmlSecOpenSSLKeyDataEcdsaGetEvp(data);
    xmlSecAssert2((pKey == NULL) || (EVP_PKEY_base_id(pKey) == EVP_PKEY_EC), NULL);

    return((pKey != NULL) ? EVP_PKEY_get0_EC_KEY(pKey) : NULL);
#else /* XMLSEC_OPENSSL_API_300 */
    UNREFERENCED_PARAMETER(data);
    xmlSecNotImplementedError("OpenSSL 3.0 does not support direct access to ECDSA key");
    return(NULL);
#endif /* XMLSEC_OPENSSL_API_300 */
}

/**
 * xmlSecOpenSSLKeyDataEcdsaAdoptEvp:
 * @data:               the pointer to ECDSA key data.
 * @pKey:               the pointer to OpenSSL EVP key.
 *
 * Sets the ECDSA key data value to OpenSSL EVP key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLKeyDataEcdsaAdoptEvp(xmlSecKeyDataPtr data, EVP_PKEY* pKey) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcdsaId), -1);
    xmlSecAssert2(pKey != NULL, -1);
    xmlSecAssert2(EVP_PKEY_base_id(pKey) == EVP_PKEY_EC, -1);

    return(xmlSecOpenSSLEvpKeyDataAdoptEvp(data, pKey));
}

/**
 * xmlSecOpenSSLKeyDataEcdsaGetEvp:
 * @data:               the pointer to ECDSA key data.
 *
 * Gets the OpenSSL EVP key from ECDSA key data.
 *
 * Returns: pointer to OpenSSL EVP key or NULL if an error occurs.
 */
EVP_PKEY*
xmlSecOpenSSLKeyDataEcdsaGetEvp(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcdsaId), NULL);

    return(xmlSecOpenSSLEvpKeyDataGetEvp(data));
}

static int
xmlSecOpenSSLKeyDataEcdsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcdsaId), -1);

    return(xmlSecOpenSSLEvpKeyDataInitialize(data));
}

static int
xmlSecOpenSSLKeyDataEcdsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataEcdsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataEcdsaId), -1);

    return(xmlSecOpenSSLEvpKeyDataDuplicate(dst, src));
}

static void
xmlSecOpenSSLKeyDataEcdsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcdsaId));

    xmlSecOpenSSLEvpKeyDataFinalize(data);
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataEcdsaGetType(xmlSecKeyDataPtr data ATTRIBUTE_UNUSED) {
    UNREFERENCED_PARAMETER(data);
    /* XXX-MAK: Fix this. */
    return(xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate);
}

static xmlSecSize
xmlSecOpenSSLKeyDataEcdsaGetSize(xmlSecKeyDataPtr data) {
#ifndef XMLSEC_OPENSSL_API_300
    const EC_GROUP *group;
    const EC_KEY *ecdsa;
    int ret;
#else /* XMLSEC_OPENSSL_API_300 */
    const EVP_PKEY* pKey;
#endif /* XMLSEC_OPENSSL_API_300 */
    BIGNUM * order = NULL;
    int numBits;
    xmlSecSize res;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcdsaId), 0);

#ifndef XMLSEC_OPENSSL_API_300
    ecdsa = xmlSecOpenSSLKeyDataEcdsaGetEcdsa(data);
    if(ecdsa == NULL) {
        return(0);
    }

    group = EC_KEY_get0_group(ecdsa);
    if(group == NULL) {
        xmlSecOpenSSLError("EC_KEY_get0_group", xmlSecKeyDataGetName(data));
        return(0);
    }

    order = BN_new();
    if(order == NULL) {
        xmlSecOpenSSLError("BN_new", xmlSecKeyDataGetName(data));
        return(0);
    }

    ret = EC_GROUP_get_order(group, order, NULL);
    if(ret != 1) {
        xmlSecOpenSSLError("EC_GROUP_get_order", xmlSecKeyDataGetName(data));
        BN_clear_free(order);
        return(0);
    }
#else /* XMLSEC_OPENSSL_API_300 */
    pKey = xmlSecOpenSSLKeyDataEcdsaGetEvp(data);
    xmlSecAssert2(pKey != NULL, 0);

    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_EC_ORDER, &order) != 1) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(ec_order)", xmlSecKeyDataGetName(data));
        return(0);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    xmlSecAssert2(order != NULL, 0);
    numBits = BN_num_bytes(order);
    BN_clear_free(order);

    if(numBits < 0) {
        xmlSecOpenSSLError("BN_num_bits", xmlSecKeyDataGetName(data));
        return(0);
    }

    XMLSEC_SAFE_CAST_INT_TO_SIZE(numBits, res, return(0), xmlSecKeyDataGetName(data));
    return(res);
}

static void
xmlSecOpenSSLKeyDataEcdsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcdsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== ecdsa key: size = %lu\n",
            XMLSEC_UL_BAD_CAST(xmlSecOpenSSLKeyDataEcdsaGetSize(data)));
}

static void
xmlSecOpenSSLKeyDataEcdsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataEcdsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<ECDSAKeyValue size=\"%lu\" />\n",
            XMLSEC_UL_BAD_CAST(xmlSecOpenSSLKeyDataEcdsaGetSize(data)));
}

#endif /* XMLSEC_NO_ECDSA */

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
static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataRsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecOpenSSLEvpKeyDataSize,

    /* data */
    xmlSecNameRSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
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
 * xmlSecOpenSSLKeyDataRsaAdoptRsa:
 * @data:               the pointer to RSA key data.
 * @rsa:                the pointer to OpenSSL RSA key.
 *
 * Sets the value of RSA key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLKeyDataRsaAdoptRsa(xmlSecKeyDataPtr data, RSA* rsa) {
#ifndef XMLSEC_OPENSSL_API_300
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
#else /* XMLSEC_OPENSSL_API_300 */
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(rsa);
    xmlSecNotImplementedError("OpenSSL 3.0 does not support direct access to RSA key");
    return(-1);
#endif /* XMLSEC_OPENSSL_API_300 */
}

/**
 * xmlSecOpenSSLKeyDataRsaGetRsa:
 * @data:               the pointer to RSA key data.
 *
 * Gets the OpenSSL RSA key from RSA key data.
 *
 * Returns: pointer to OpenSSL RSA key or NULL if an error occurs.
 */
RSA*
xmlSecOpenSSLKeyDataRsaGetRsa(xmlSecKeyDataPtr data) {
#ifndef XMLSEC_OPENSSL_API_300
    EVP_PKEY* pKey;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), NULL);

    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(data);
    xmlSecAssert2((pKey == NULL) || (EVP_PKEY_base_id(pKey) == EVP_PKEY_RSA), NULL);

    return((pKey != NULL) ? EVP_PKEY_get0_RSA(pKey) : NULL);
#else /* XMLSEC_OPENSSL_API_300 */
    UNREFERENCED_PARAMETER(data);
    xmlSecNotImplementedError("OpenSSL 3.0 does not support direct access to RSA key");
    return(NULL);
#endif /* XMLSEC_OPENSSL_API_300 */
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
    xmlSecKeyDataPtr data = NULL;
    xmlNodePtr cur;
#ifndef XMLSEC_OPENSSL_API_300
    RSA *rsa = NULL;
#else /* XMLSEC_OPENSSL_API_300 */
    EVP_PKEY* pKey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    OSSL_PARAM_BLD* param_bld = NULL;
    OSSL_PARAM* params = NULL;
#endif /* XMLSEC_OPENSSL_API_300 */
    BIGNUM* n = NULL;
    BIGNUM* e = NULL;
    BIGNUM* d = NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataRsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_KEY_DATA,
                xmlSecKeyDataKlassGetName(id),
                "Key data value is already set");
        goto done;
    }

    cur = xmlSecGetNextElementNode(node->children);

    /* first is Modulus node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  xmlSecNodeRSAModulus, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeRSAModulus, xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &n) == NULL) {
        xmlSecInternalError2("xmlSecOpenSSLNodeGetBNValue",
                             xmlSecKeyDataKlassGetName(id),
                             "node=%s", xmlSecErrorsSafeString(xmlSecNodeRSAModulus));
        goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is Exponent node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeRSAExponent, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeRSAExponent, xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(xmlSecOpenSSLNodeGetBNValue(cur, &e) == NULL) {
        xmlSecInternalError2("xmlSecOpenSSLNodeGetBNValue",
                             xmlSecKeyDataKlassGetName(id),
                              "node=%s", xmlSecErrorsSafeString(xmlSecNodeRSAExponent));
        goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeRSAPrivateExponent, xmlSecNs))) {
        /* next is X node. It is REQUIRED for private key but
         * we are not sure exactly what do we read */
        if(xmlSecOpenSSLNodeGetBNValue(cur, &d) == NULL) {
            xmlSecInternalError2("xmlSecOpenSSLNodeGetBNValue",
                                 xmlSecKeyDataKlassGetName(id),
                                 "node=%s", xmlSecErrorsSafeString(xmlSecNodeRSAPrivateExponent));
            goto done;
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
        xmlSecInternalError("xmlSecKeyDataCreate", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

#ifndef XMLSEC_OPENSSL_API_300
    rsa = RSA_new();
    if(rsa == NULL) {
        xmlSecOpenSSLError("RSA_new", xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = RSA_set0_key(rsa, n, e, d);
    if(ret == 0) {
        xmlSecOpenSSLError("RSA_set0_key", xmlSecKeyDataGetName(data));
        goto done;
    }
    n = NULL;
    e = NULL;
    d = NULL;

    ret = xmlSecOpenSSLKeyDataRsaAdoptRsa(data, rsa);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataRsaAdoptRsa",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    rsa = NULL;

#else /* XMLSEC_OPENSSL_API_300 */
    param_bld = OSSL_PARAM_BLD_new();
    if(param_bld == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_new", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, n) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(n)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, e) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(e)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_D, d) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(d)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if(params == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_to_param", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ctx = EVP_PKEY_CTX_new_from_name(xmlSecOpenSSLGetLibCtx(), "RSA", NULL);
    if(ctx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_name", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = EVP_PKEY_fromdata_init(ctx);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_fromdata_init", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = EVP_PKEY_fromdata(ctx, &pKey, EVP_PKEY_KEYPAIR, params);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_fromdata", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = xmlSecOpenSSLKeyDataRsaAdoptEvp(data, pKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaAdoptEvp", xmlSecKeyDataGetName(data));
        goto done;
    }
    pKey = NULL;
#endif /* XMLSEC_OPENSSL_API_300 */
 
    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    data = NULL;
    res = 0;

done:
#ifndef XMLSEC_OPENSSL_API_300
    if(rsa != NULL) {
        RSA_free(rsa);
    }
#else /* XMLSEC_OPENSSL_API_300 */
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
#endif /* XMLSEC_OPENSSL_API_300 */
    if(n != NULL) {
        BN_clear_free(n);
    }
    if(e != NULL) {
        BN_clear_free(e);
    }
    if(d != NULL) {
        BN_clear_free(d);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

static int
xmlSecOpenSSLKeyDataRsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                            xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlNodePtr cur;
#ifndef XMLSEC_OPENSSL_API_300
    RSA* rsa = NULL;
    const BIGNUM* n = NULL;
    const BIGNUM* e = NULL;
    const BIGNUM* d = NULL;
#else /* XMLSEC_OPENSSL_API_300 */
    EVP_PKEY* pKey = NULL;
    BIGNUM* n = NULL;
    BIGNUM* e = NULL;
    BIGNUM* d = NULL;
#endif
    int ret;
    int res = -1;

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataRsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(((xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate) & keyInfoCtx->keyReq.keyType) == 0) {
        /* we can have only private key or public key */
        return(-1);
    }

#ifndef XMLSEC_OPENSSL_API_300
    rsa = xmlSecOpenSSLKeyDataRsaGetRsa(xmlSecKeyGetValue(key));
    xmlSecAssert2(rsa != NULL, -1);

    RSA_get0_key(rsa, &n, &e, &d);
#else /* XMLSEC_OPENSSL_API_300 */
    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(xmlSecKeyGetValue(key));
    xmlSecAssert2(pKey != NULL, -1);

    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_N, &n) != 1) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(n)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_E, &e) != 1) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(e)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_D, &d) != 1) {
        /* ignore the error -- public key doesn't have private component */
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    /* first is Modulus node */
    cur = xmlSecAddChild(node, xmlSecNodeRSAModulus, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError2("xmlSecAddChild",
                             xmlSecKeyDataKlassGetName(id),
                             "node=%s", xmlSecErrorsSafeString(xmlSecNodeRSAModulus));
        goto done;
    }

    ret = xmlSecOpenSSLNodeSetBNValue(cur, n, 1);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecOpenSSLNodeSetBNValue",
                             xmlSecKeyDataKlassGetName(id),
                             "node=%s", xmlSecErrorsSafeString(xmlSecNodeRSAModulus));
        goto done;
    }

    /* next is Exponent node. */
    cur = xmlSecAddChild(node, xmlSecNodeRSAExponent, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError2("xmlSecAddChild",
                             xmlSecKeyDataKlassGetName(id),
                             "node=%s", xmlSecErrorsSafeString(xmlSecNodeRSAExponent));
        goto done;
    }
    ret = xmlSecOpenSSLNodeSetBNValue(cur, e, 1);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecOpenSSLNodeSetBNValue",
                             xmlSecKeyDataKlassGetName(id),
                             "node=%s", xmlSecErrorsSafeString(xmlSecNodeRSAExponent));
        goto done;
    }

    /* next is PrivateExponent node: write it ONLY for private keys and ONLY if it is requested */
    if(((keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypePrivate) != 0) && (d != NULL)) {
        cur = xmlSecAddChild(node, xmlSecNodeRSAPrivateExponent, xmlSecNs);
        if(cur == NULL) {
            xmlSecInternalError2("xmlSecAddChild",
                                 xmlSecKeyDataKlassGetName(id),
                                 "node=%s", xmlSecErrorsSafeString(xmlSecNodeRSAPrivateExponent));
            goto done;
        }
        ret = xmlSecOpenSSLNodeSetBNValue(cur, d, 1);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecOpenSSLNodeSetBNValue",
                                 xmlSecKeyDataKlassGetName(id),
                                 "node=%s", xmlSecErrorsSafeString(xmlSecNodeRSAPrivateExponent));
            goto done;
        }
    }

    /* success */
    res = 0;

done:
#ifdef XMLSEC_OPENSSL_API_300
    if(n != NULL) {
        BN_clear_free(n);
    }
    if(e != NULL) {
        BN_clear_free(e);
    }
    if(d != NULL) {
        BN_clear_free(d);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    return(res);
}

static int
xmlSecOpenSSLKeyDataRsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
#ifndef XMLSEC_OPENSSL_API_300
    RSA* rsa = NULL;
#else /* XMLSEC_OPENSSL_API_300 */
    EVP_PKEY_CTX* pctx = NULL;
    OSSL_PARAM_BLD* param_bld = NULL;
    OSSL_PARAM* params = NULL;
    EVP_PKEY* pKey = NULL;
#endif /* XMLSEC_OPENSSL_API_300 */
    BIGNUM* e = NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);
    UNREFERENCED_PARAMETER(type);

    /* create exponent */
    e = BN_new();
    if(e == NULL) {
        xmlSecOpenSSLError("BN_new", xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = BN_set_word(e, RSA_F4);
    if(ret != 1){
        xmlSecOpenSSLError("BN_set_word", xmlSecKeyDataGetName(data));
        goto done;
    }

#ifndef XMLSEC_OPENSSL_API_300
    rsa = RSA_new();
    if(rsa == NULL) {
        xmlSecOpenSSLError("RSA_new", xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = RSA_generate_key_ex(rsa, sizeBits, e, NULL);
    if(ret != 1) {
        xmlSecOpenSSLError2("RSA_generate_key_ex",
                            xmlSecKeyDataGetName(data),
                            "sizeBits=%lu", XMLSEC_UL_BAD_CAST(sizeBits));
        goto done;
    }

    ret = xmlSecOpenSSLKeyDataRsaAdoptRsa(data, rsa);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataRsaAdoptRsa",
                            xmlSecKeyDataGetName(data));
        goto done;
    }
    rsa = NULL;

#else /* XMLSEC_OPENSSL_API_300 */
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
#ifndef XMLSEC_NO_SIZE_T
    if(OSSL_PARAM_BLD_push_size_t(param_bld, OSSL_PKEY_PARAM_BITS, sizeBits) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_size_t(bits)", xmlSecKeyDataGetName(data));
        goto done;
    }
#else /* XMLSEC_NO_SIZE_T */
    if(OSSL_PARAM_BLD_push_uint(param_bld, OSSL_PKEY_PARAM_BITS, sizeBits) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_uint(bits)", xmlSecKeyDataGetName(data));
        goto done;
    }
#endif /* XMLSEC_NO_SIZE_T */

    if(OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, e) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_BN(e)", xmlSecKeyDataGetName(data));
        goto done;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if(params == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_to_param", xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_CTX_set_params(pctx, params);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_set_param", xmlSecKeyDataGetName(data));
        goto done;
    }
    ret = EVP_PKEY_generate(pctx, &pKey);
    if(ret <= 0) {
        xmlSecOpenSSLError2("EVP_PKEY_generate",
            xmlSecKeyDataGetName(data),
            "sizeBits=%lu", XMLSEC_UL_BAD_CAST(sizeBits));
        goto done;
    }
    ret = xmlSecOpenSSLKeyDataRsaAdoptEvp(data, pKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataDsaAdoptEvp",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    pKey = NULL;
#endif /* XMLSEC_OPENSSL_API_300 */

    /* success */
    res = 0;

done:
#ifndef XMLSEC_OPENSSL_API_300
    if(rsa != NULL) {
        RSA_free(rsa);
    }
#else /* XMLSEC_OPENSSL_API_300 */
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
#endif /* XMLSEC_OPENSSL_API_300 */ 
    if(e != NULL) {
        BN_clear_free(e);
    } 
    return(res);
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataRsaGetType(xmlSecKeyDataPtr data) {
#ifndef XMLSEC_OPENSSL_API_300
    RSA* rsa = NULL;
    const BIGNUM* n = NULL;
    const BIGNUM* e = NULL;
    const BIGNUM* d = NULL;
#else /* XMLSEC_OPENSSL_API_300 */
    EVP_PKEY* pKey = NULL;
    BIGNUM* n = NULL;
    BIGNUM* e = NULL;
    BIGNUM* d = NULL;
#endif /* XMLSEC_OPENSSL_API_300 */
    xmlSecKeyDataType res = xmlSecKeyDataTypeUnknown;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), xmlSecKeyDataTypeUnknown);

#ifndef XMLSEC_OPENSSL_API_300
    rsa = xmlSecOpenSSLKeyDataRsaGetRsa(data);
    if(rsa == NULL) {
        goto done;
    }

    RSA_get0_key(rsa, &n, &e, &d);
    if(n != NULL && e != NULL) {
        if(d != NULL) {
            res = xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic;
        } else if(RSA_test_flags(rsa, (RSA_FLAG_EXT_PKEY)) != 0) {
            /*
             * !!! HACK !!! Also see DSA key
             * We assume here that engine *always* has private key.
             * This might be incorrect but it seems that there is no
             * way to ask engine if given key is private or not.
             */
            res = xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic;
        } else {
            res = xmlSecKeyDataTypePublic;
        }
    }
#else /* XMLSEC_OPENSSL_API_300 */
    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(data);
    xmlSecAssert2(pKey != NULL, xmlSecKeyDataTypeUnknown);

    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_N, &n) != 1) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(n)", xmlSecKeyDataGetName(data));
        goto done;
    }
    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_E, &e) != 1) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_parae(e)", xmlSecKeyDataGetName(data));
        goto done;
    }
    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_D, &d)  != 1) {
        /* ignore the error since public keys don't have private component */
    }
    if(n != NULL && e != NULL) {
        if(d != NULL) {
            res = xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic;
        } else {
            res = xmlSecKeyDataTypePublic;
        }
    }
#endif /* XMLSEC_OPENSSL_API_300 */

done: 
#ifdef XMLSEC_OPENSSL_API_300
    if(n != NULL) {
        BN_clear_free(n);
    }
    if(e != NULL) {
        BN_clear_free(e);
    }
    if(d != NULL) {
        BN_clear_free(d);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    return(res);
}

static xmlSecSize
xmlSecOpenSSLKeyDataRsaGetSize(xmlSecKeyDataPtr data) {
#ifndef XMLSEC_OPENSSL_API_300
    RSA* rsa = NULL;
    const BIGNUM* n = NULL;
#else /* XMLSEC_OPENSSL_API_300 */
    EVP_PKEY* pKey = NULL;
    BIGNUM* n = NULL;
#endif /* XMLSEC_OPENSSL_API_300 */
    int numBits;
    xmlSecSize res;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId), 0);

#ifndef XMLSEC_OPENSSL_API_300
    rsa = xmlSecOpenSSLKeyDataRsaGetRsa(data);
    if(rsa == NULL) {
        return(0);
    }

    RSA_get0_key(rsa, &n, NULL, NULL);
    if(n == NULL) {
        return(0);
    }
    numBits = BN_num_bits(n);
#else /* XMLSEC_OPENSSL_API_300 */
    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(data);
    xmlSecAssert2(pKey != NULL, 0);

    if(EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_N, &n) != 1) {
        xmlSecOpenSSLError("EVP_PKEY_get_bn_param(n)", xmlSecKeyDataGetName(data));
        return(0);
    }

    numBits = BN_num_bits(n);
    BN_clear_free(n);
#endif /* XMLSEC_OPENSSL_API_300 */

    if(numBits < 0) {
        xmlSecOpenSSLError("BN_num_bits", xmlSecKeyDataGetName(data));
        return(0);
    }

    XMLSEC_SAFE_CAST_INT_TO_SIZE(numBits, res, return(0), xmlSecKeyDataGetName(data));
    return(res);
}

static void
xmlSecOpenSSLKeyDataRsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== rsa key: size = %lu\n",
            XMLSEC_UL_BAD_CAST(xmlSecOpenSSLKeyDataRsaGetSize(data)));
}

static void
xmlSecOpenSSLKeyDataRsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<RSAKeyValue size=\"%lu\" />\n",
            XMLSEC_UL_BAD_CAST(xmlSecOpenSSLKeyDataRsaGetSize(data)));
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
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
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
xmlSecOpenSSLKeyDataGost2001GetType(xmlSecKeyDataPtr data) {
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

    fprintf(output, "=== gost key: size = %lu\n",
            XMLSEC_UL_BAD_CAST(xmlSecOpenSSLKeyDataGost2001GetSize(data)));
}

static void
xmlSecOpenSSLKeyDataGost2001DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGost2001Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<GOST2001KeyValue size=\"%lu\" />\n",
            XMLSEC_UL_BAD_CAST(xmlSecOpenSSLKeyDataGost2001GetSize(data)));
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
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
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
xmlSecOpenSSLKeyDataGostR3410_2012_256GetType(xmlSecKeyDataPtr data) {
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

    fprintf(output, "=== gost key: size = %lu\n",
            XMLSEC_UL_BAD_CAST(xmlSecOpenSSLKeyDataGostR3410_2012_256GetSize(data)));
}

static void
xmlSecOpenSSLKeyDataGostR3410_2012_256DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGostR3410_2012_256Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<GOST2012_256KeyValue size=\"%lu\" />\n",
            XMLSEC_UL_BAD_CAST(xmlSecOpenSSLKeyDataGostR3410_2012_256GetSize)(data));
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
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
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
xmlSecOpenSSLKeyDataGostR3410_2012_512GetType(xmlSecKeyDataPtr data) {
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

    fprintf(output, "=== gost key: size = %lu\n",
            XMLSEC_UL_BAD_CAST(xmlSecOpenSSLKeyDataGostR3410_2012_512GetSize(data)));
}

static void
xmlSecOpenSSLKeyDataGostR3410_2012_512DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataGostR3410_2012_512Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<GOST2012_512KeyValue size=\"%lu\" />\n",
            XMLSEC_UL_BAD_CAST(xmlSecOpenSSLKeyDataGostR3410_2012_512GetSize(data)));
}

#endif /* XMLSEC_NO_GOST2012 */

