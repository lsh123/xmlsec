/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_gcrypt_crypto
 * @brief Private/public keys implementation for GCrypt.
 */
#include "globals.h"

#include <string.h>

#include <gcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/base64.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/gcrypt/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"

/******************************************************************************
 *
 * Helpers
 *
  *****************************************************************************/
static gcry_sexp_t             xmlSecGCryptAsymSExpDup    (gcry_sexp_t sexp);


/******************************************************************************
 *
 * Internal GCrypt asym key CTX
 *
  *****************************************************************************/
typedef struct _xmlSecGCryptAsymKeyDataCtx       xmlSecGCryptAsymKeyDataCtx,
                                                *xmlSecGCryptAsymKeyDataCtxPtr;
struct _xmlSecGCryptAsymKeyDataCtx {
    gcry_sexp_t pub_key;
    gcry_sexp_t priv_key;
};

/******************************************************************************
 *
 * GCrypt asym key data (dsa/rsa/ec)
 *
  *****************************************************************************/
XMLSEC_KEY_DATA_DECLARE(GCryptAsymKeyData, xmlSecGCryptAsymKeyDataCtx)
#define xmlSecGCryptAsymKeyDataSize XMLSEC_KEY_DATA_SIZE(GCryptAsymKeyData)

static int              xmlSecGCryptAsymKeyDataInitialize       (xmlSecKeyDataPtr data);
static int              xmlSecGCryptAsymKeyDataDuplicate        (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
static void             xmlSecGCryptAsymKeyDataFinalize         (xmlSecKeyDataPtr data);

static int              xmlSecGCryptAsymKeyDataAdoptKey         (xmlSecKeyDataPtr data,
                                                                 gcry_sexp_t key_pair);
static int              xmlSecGCryptAsymKeyDataAdoptKeyPair     (xmlSecKeyDataPtr data,
                                                                 gcry_sexp_t pub_key,
                                                                 gcry_sexp_t priv_key);
static gcry_sexp_t      xmlSecGCryptAsymKeyDataGetPublicKey     (xmlSecKeyDataPtr data);
static gcry_sexp_t      xmlSecGCryptAsymKeyDataGetPrivateKey    (xmlSecKeyDataPtr data);
static int              xmlSecGCryptAsymKeyDataGenerate         (xmlSecKeyDataPtr data,
                                                                 const char * alg,
                                                                 xmlSecSize key_size);
static xmlSecKeyDataType xmlSecGCryptAsymKeyDataGetType         (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecGCryptAsymKeyDataGetSize          (xmlSecKeyDataPtr data);


static int
xmlSecGCryptAsymKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecGCryptAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGCryptAsymKeyDataSize), -1);

    ctx = xmlSecGCryptAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecGCryptAsymKeyDataCtx));

    return(0);
}

static int
xmlSecGCryptAsymKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecGCryptAsymKeyDataCtxPtr ctxDst;
    xmlSecGCryptAsymKeyDataCtxPtr ctxSrc;

    xmlSecAssert2(xmlSecKeyDataIsValid(dst), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(dst, xmlSecGCryptAsymKeyDataSize), -1);
    xmlSecAssert2(xmlSecKeyDataIsValid(src), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(src, xmlSecGCryptAsymKeyDataSize), -1);

    ctxDst = xmlSecGCryptAsymKeyDataGetCtx(dst);
    xmlSecAssert2(ctxDst != NULL, -1);
    xmlSecAssert2(ctxDst->pub_key == NULL, -1);
    xmlSecAssert2(ctxDst->priv_key == NULL, -1);

    ctxSrc = xmlSecGCryptAsymKeyDataGetCtx(src);
    xmlSecAssert2(ctxSrc != NULL, -1);

    if(ctxSrc->pub_key != NULL) {
        ctxDst->pub_key = xmlSecGCryptAsymSExpDup(ctxSrc->pub_key);
        if(ctxDst->pub_key == NULL) {
            xmlSecInternalError("xmlSecGCryptAsymSExpDup(pub_key)",
                                xmlSecKeyDataGetName(dst));
            return(-1);
        }
    }

    if(ctxSrc->priv_key != NULL) {
        ctxDst->priv_key = xmlSecGCryptAsymSExpDup(ctxSrc->priv_key);
        if(ctxDst->priv_key == NULL) {
            xmlSecInternalError("xmlSecGCryptAsymSExpDup(priv_key)",
                                xmlSecKeyDataGetName(dst));
            return(-1);
        }
    }

    return(0);
}

static void
xmlSecGCryptAsymKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecGCryptAsymKeyDataCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecGCryptAsymKeyDataSize));

    ctx = xmlSecGCryptAsymKeyDataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    if(ctx->pub_key != NULL) {
        gcry_sexp_release(ctx->pub_key);
    }
    if(ctx->priv_key != NULL) {
        gcry_sexp_release(ctx->priv_key);
    }
    memset(ctx, 0, sizeof(xmlSecGCryptAsymKeyDataCtx));
}

static int
xmlSecGCryptAsymKeyDataAdoptKey(xmlSecKeyDataPtr data, gcry_sexp_t key_pair) {
    xmlSecGCryptAsymKeyDataCtxPtr ctx;
    gcry_sexp_t pub_key = NULL;
    gcry_sexp_t priv_key = NULL;
    int res = -1;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGCryptAsymKeyDataSize), -1);
    xmlSecAssert2(key_pair != NULL, -1);

    ctx = xmlSecGCryptAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    /* split the key pair, public part should be always present, private might
       not be present */
    pub_key = gcry_sexp_find_token(key_pair, "public-key", 0);
    if(pub_key == NULL) {
        xmlSecGCryptError("gcry_sexp_find_token(public-key)", (gcry_error_t)GPG_ERR_NO_ERROR, NULL);
        goto done;
    }
    priv_key = gcry_sexp_find_token(key_pair, "private-key", 0);

    /* assign */
    if(xmlSecGCryptAsymKeyDataAdoptKeyPair(data, pub_key, priv_key) < 0) {
        xmlSecInternalError("xmlSecGCryptAsymKeyDataAdoptKeyPair", NULL);
        goto done;
    }
    pub_key = NULL; /* data owns it now */
    priv_key = NULL; /* data owns it now */

   /* Adopt functions assume ownership on success thus the caller would expect this to be released */
    gcry_sexp_release(key_pair);

    /* success */
    res = 0;

done:
    if(pub_key != NULL) {
        gcry_sexp_release(pub_key);
    }

    if(priv_key != NULL) {
        gcry_sexp_release(priv_key);
    }

    /* done */
    return(res);
}

static int
xmlSecGCryptAsymKeyDataAdoptKeyPair(xmlSecKeyDataPtr data, gcry_sexp_t pub_key, gcry_sexp_t priv_key) {
    xmlSecGCryptAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGCryptAsymKeyDataSize), -1);
    xmlSecAssert2(pub_key != NULL, -1); /* public key should present always */
/*
    aleksey - we don't set optional parameters for RSA keys (p, k, u) and
    because of that we can't actually test the key

    xmlSecAssert2(((priv_key == NULL) || (gcry_pk_testkey(priv_key) == GPG_ERR_NO_ERROR)), -1);
*/

    ctx = xmlSecGCryptAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    /* release prev values and assign new ones */
    if(ctx->pub_key != NULL) {
        gcry_sexp_release(ctx->pub_key);
    }
    if(ctx->priv_key != NULL) {
        gcry_sexp_release(ctx->priv_key);
    }

    ctx->pub_key = pub_key;
    ctx->priv_key = priv_key;

    /* done */
    return(0);
}

static gcry_sexp_t
xmlSecGCryptAsymKeyDataGetPublicKey(xmlSecKeyDataPtr data) {
    xmlSecGCryptAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGCryptAsymKeyDataSize), NULL);

    ctx = xmlSecGCryptAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->pub_key);
}

static gcry_sexp_t
xmlSecGCryptAsymKeyDataGetPrivateKey(xmlSecKeyDataPtr data) {
    xmlSecGCryptAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGCryptAsymKeyDataSize), NULL);

    ctx = xmlSecGCryptAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->priv_key);
}

static int
xmlSecGCryptAsymKeyDataGenerate(xmlSecKeyDataPtr data, const char * alg, xmlSecSize key_size) {
    xmlSecGCryptAsymKeyDataCtxPtr ctx;
    gcry_sexp_t key_spec = NULL;
    gcry_sexp_t key_pair = NULL;
    gcry_error_t err;
    int key_len;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGCryptAsymKeyDataSize), -1);
    xmlSecAssert2(alg != NULL, -1);
    xmlSecAssert2(key_size > 0, -1);

    ctx = xmlSecGCryptAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_INT(key_size, key_len, goto done, NULL);

    err = gcry_sexp_build(&key_spec, NULL,
                          "(genkey (%s (nbits %d)(transient-key)))",
                          alg, key_len);
    if((err != GPG_ERR_NO_ERROR) || (key_spec == NULL)) {
        xmlSecGCryptError("gcry_sexp_build(genkey)", err, NULL);
        goto done;
    }

    err = gcry_pk_genkey(&key_pair, key_spec);
    if((err != GPG_ERR_NO_ERROR) || (key_pair == NULL)) {
        xmlSecGCryptError("gcry_pk_genkey", err, NULL);
        goto done;
    }

    ret = xmlSecGCryptAsymKeyDataAdoptKey(data, key_pair);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptAsymKeyDataAdopt", NULL);
        goto done;
    }
    key_pair = NULL; /* now owned by data */

    /* success */
    res = 0;

done:
    if(key_spec != NULL) {
        gcry_sexp_release(key_spec);
    }
    if(key_pair != NULL) {
        gcry_sexp_release(key_pair);
    }

    return(res);
}

static xmlSecKeyDataType
xmlSecGCryptAsymKeyDataGetType(xmlSecKeyDataPtr data) {
    xmlSecGCryptAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGCryptAsymKeyDataSize), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecGCryptAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, xmlSecKeyDataTypeUnknown);

    if((ctx->priv_key != NULL) && (ctx->pub_key != NULL)) {
        return (xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
    } else if(ctx->pub_key != NULL) {
        return (xmlSecKeyDataTypePublic);
    }

    return (xmlSecKeyDataTypeUnknown);
}

static xmlSecSize
xmlSecGCryptAsymKeyDataGetSize(xmlSecKeyDataPtr data) {
    xmlSecGCryptAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGCryptAsymKeyDataSize), 0);

    ctx = xmlSecGCryptAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    if(ctx->priv_key != NULL) {
        return gcry_pk_get_nbits(ctx->priv_key);
    } else if(ctx->pub_key != NULL) {
        return gcry_pk_get_nbits(ctx->pub_key);
    }
    return(0);
}

/******************************************************************************
 *
 * helper functions
 *
  *****************************************************************************/
static gcry_sexp_t
xmlSecGCryptAsymSExpDup(gcry_sexp_t pKey) {
    gcry_sexp_t res = NULL;
    xmlSecByte *buf = NULL;
    gcry_error_t err;
    size_t size;

    xmlSecAssert2(pKey != NULL, NULL);

    size = gcry_sexp_sprint(pKey, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    if(size == 0) {
        xmlSecGCryptError("gcry_sexp_sprint", (gcry_error_t)GPG_ERR_NO_ERROR, NULL);
        goto done;
    }

    buf = (xmlSecByte *)xmlMalloc(size);
    if(buf == NULL) {
        xmlSecMallocError(size, NULL);
        goto done;
    }

    size = gcry_sexp_sprint(pKey, GCRYSEXP_FMT_ADVANCED, buf, size);
    if(size == 0) {
        xmlSecGCryptError2("gcry_sexp_sprint", (gcry_error_t)GPG_ERR_NO_ERROR, NULL,
                           "size" XMLSEC_SIZE_T_FMT, size);
        goto done;
    }

    err = gcry_sexp_new(&res, buf, size, 1);
    if((err != GPG_ERR_NO_ERROR) || (res == NULL)) {
        xmlSecGCryptError("gcry_sexp_new", err, NULL);
        goto done;
    }

done:
    if(buf != NULL) {
        xmlSecMemCleanse(buf, size);
        xmlFree(buf);
    }
    return (res);
}

/**
 * @brief Checks that a GCrypt key S-expression is of the expected algorithm type.
 * @param key the pointer to the GCrypt key S-expression (public key, private key, or key pair).
 * @param alg the expected algorithm token ("dsa", "rsa", or "ecdsa").
 * @return 0 if the key is of the expected type or -1 otherwise.
 */
static int
xmlSecGCryptAsymKeyDataCheckKeyAlg(gcry_sexp_t key, const char* alg) {
    gcry_sexp_t tok;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(alg != NULL, -1);

    /* the algorithm token (dsa/rsa/ecdsa) is present in the public-key,
       private-key and key-pair S-expressions alike, so its presence
       unambiguously identifies the key type */
    tok = gcry_sexp_find_token(key, alg, 0);
    if(tok == NULL) {
        return(-1);
    }
    gcry_sexp_release(tok);

    /* success */
    return(0);
}

/**
 * @brief Converts MPI to CryptoBinary string
 * @param sexp the sexp
 * @param tok the token
 * @param buf the output buffer.
 *
 * (http://www.w3.org/TR/xmldsig-core/#sec-CryptoBinary).
 *
 * @return 0 on success or -1 otherwise.
 */
static int
xmlSecGCryptSetSExpTokValue(const gcry_sexp_t sexp, const char * tok,
                            xmlSecBufferPtr buf)
{
    gcry_sexp_t val = NULL;
    gcry_mpi_t mpi = NULL;
    xmlSecSize writtenSize = 0;
    gcry_error_t err;
    int ret;
    int res = -1;

    xmlSecAssert2(sexp != NULL, -1);
    xmlSecAssert2(tok != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    val = gcry_sexp_find_token(sexp, tok, 0);
    if(val == NULL) {
        xmlSecGCryptError2("gcry_sexp_find_token", (gcry_error_t)GPG_ERR_NO_ERROR, NULL,
                           "tok=%s", xmlSecErrorsSafeString(tok));
        goto done;
    }

    mpi = gcry_sexp_nth_mpi(val, 1, GCRYMPI_FMT_USG);
    if(mpi == NULL) {
        xmlSecGCryptError2("gcry_sexp_nth_mpi", (gcry_error_t)GPG_ERR_NO_ERROR, NULL,
                           "tok=%s", xmlSecErrorsSafeString(tok));
        goto done;
    }

    /* get the estimated size for output buffer */
    writtenSize = 0;
    err = gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &writtenSize, mpi);
    if((err != GPG_ERR_NO_ERROR) || (writtenSize == 0)) {
        xmlSecGCryptError2("gcry_mpi_print", err, NULL,
                           "tok=%s", xmlSecErrorsSafeString(tok));
        goto done;
    }

    /* allocate the output buffer */
    ret = xmlSecBufferSetMaxSize(buf, writtenSize + 1);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL,
            "size=" XMLSEC_SIZE_FMT, (writtenSize + 1));
        goto done;
    }

    /* write to the buffer */
    writtenSize = 0;
    err = gcry_mpi_print(GCRYMPI_FMT_USG,
            xmlSecBufferGetData(buf),
            xmlSecBufferGetMaxSize(buf),
            &writtenSize, mpi);
    if((err != GPG_ERR_NO_ERROR) || (writtenSize == 0)) {
        xmlSecGCryptError2("gcry_mpi_print", err, NULL,
                           "tok=%s", xmlSecErrorsSafeString(tok));
        goto done;
    }

    ret = xmlSecBufferSetSize(buf, writtenSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, writtenSize);
        goto done;
    }

    /* success */
    res = 0;

done:
    if(mpi != NULL) {
        gcry_mpi_release(mpi);
    }
    if(val != NULL) {
        gcry_sexp_release(val);
    }

    return(res);
}

#ifndef XMLSEC_NO_DSA
/******************************************************************************
 *
 * &lt;dsig:DSAKeyValue/&gt; processing
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
 *
 * The current implementation does not support Seed and PgenCounter!
 * by this the P, Q and G are *required*!
 *
  *****************************************************************************/
static int              xmlSecGCryptKeyDataDsaInitialize        (xmlSecKeyDataPtr data);
static int              xmlSecGCryptKeyDataDsaDuplicate         (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
static void             xmlSecGCryptKeyDataDsaFinalize          (xmlSecKeyDataPtr data);
static int              xmlSecGCryptKeyDataDsaXmlRead           (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecGCryptKeyDataDsaXmlWrite          (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecGCryptKeyDataDsaGenerate          (xmlSecKeyDataPtr data,
                                                                 xmlSecSize sizeBits,
                                                                 xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecGCryptKeyDataDsaGetType          (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecGCryptKeyDataDsaGetSize           (xmlSecKeyDataPtr data);
static void             xmlSecGCryptKeyDataDsaDebugDump         (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecGCryptKeyDataDsaDebugXmlDump      (xmlSecKeyDataPtr data,
                                                                 FILE* output);

static xmlSecKeyDataPtr xmlSecGCryptKeyDataDsaRead              (xmlSecKeyDataId id,
                                                                 xmlSecKeyValueDsaPtr dsaValue);
static int              xmlSecGCryptKeyDataDsaWrite             (xmlSecKeyDataId id,
                                                                 xmlSecKeyDataPtr data,
                                                                 xmlSecKeyValueDsaPtr dsaValue,
                                                                 int writePrivateKey);

static xmlSecKeyDataKlass xmlSecGCryptKeyDataDsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecGCryptAsymKeyDataSize,

    /* data */
    xmlSecNameDSAKeyValue,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefDSAKeyValue,                      /* const xmlChar* href; */
    xmlSecNodeDSAKeyValue,                      /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecGCryptKeyDataDsaInitialize,          /* xmlSecKeyDataInitMethod initialize; */
    xmlSecGCryptKeyDataDsaDuplicate,           /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecGCryptKeyDataDsaFinalize,            /* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecGCryptKeyDataDsaGenerate,            /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecGCryptKeyDataDsaGetType,             /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecGCryptKeyDataDsaGetSize,             /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* DEPRECATED xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecGCryptKeyDataDsaXmlRead,             /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecGCryptKeyDataDsaXmlWrite,            /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecGCryptKeyDataDsaDebugDump,           /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecGCryptKeyDataDsaDebugXmlDump,        /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * @brief The DSA key data klass.
 * @return pointer to DSA key data klass.
 */
xmlSecKeyDataId
xmlSecGCryptKeyDataDsaGetKlass(void) {
    return(&xmlSecGCryptKeyDataDsaKlass);
}

/**
 * @brief Sets the value of DSA key data.
 * @details On success, @p dsa_key will be owned by the @p data; on failure the
 * caller retains ownership.
 * @param data the pointer to DSA key data.
 * @param dsa_key the pointer to GCrypt DSA key.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptKeyDataDsaAdoptKey(xmlSecKeyDataPtr data, gcry_sexp_t dsa_key) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataDsaId), -1);
    xmlSecAssert2(dsa_key != NULL, -1);

    if(xmlSecGCryptAsymKeyDataCheckKeyAlg(dsa_key, "dsa") < 0) {
        xmlSecInvalidDataError("the provided key is not a DSA key", xmlSecKeyDataGetName(data));
        return(-1);
    }

    return xmlSecGCryptAsymKeyDataAdoptKey(data, dsa_key);
}


/**
 * @brief Sets the value of DSA key data.
 * @details On success, @p pub_key and @p priv_key will be owned by the @p data;
 * on failure the caller retains ownership.
 * @param data the pointer to DSA key data.
 * @param pub_key the pointer to GCrypt DSA pub key.
 * @param priv_key the pointer to GCrypt DSA priv key.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptKeyDataDsaAdoptKeyPair(xmlSecKeyDataPtr data, gcry_sexp_t pub_key, gcry_sexp_t priv_key) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataDsaId), -1);
    xmlSecAssert2(pub_key != NULL, -1);

    if(xmlSecGCryptAsymKeyDataCheckKeyAlg(pub_key, "dsa") < 0) {
        xmlSecInvalidDataError("the provided key is not a DSA key", xmlSecKeyDataGetName(data));
        return(-1);
    }
    if((priv_key != NULL) && (xmlSecGCryptAsymKeyDataCheckKeyAlg(priv_key, "dsa") < 0)) {
        xmlSecInvalidDataError("the provided key is not a DSA key", xmlSecKeyDataGetName(data));
        return(-1);
    }

    return xmlSecGCryptAsymKeyDataAdoptKeyPair(data, pub_key, priv_key);
}

/**
 * @brief Gets the GCrypt DSA public key from DSA key data.
 * @param data the pointer to DSA key data.
 * @return pointer to GCrypt public DSA key or NULL if an error occurs.
 */
gcry_sexp_t
xmlSecGCryptKeyDataDsaGetPublicKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataDsaId), NULL);
    return xmlSecGCryptAsymKeyDataGetPublicKey(data);
}

/**
 * @brief Gets the GCrypt DSA private key from DSA key data.
 * @param data the pointer to DSA key data.
 * @return pointer to GCrypt private DSA key or NULL if an error occurs.
 */
gcry_sexp_t
xmlSecGCryptKeyDataDsaGetPrivateKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataDsaId), NULL);
    return xmlSecGCryptAsymKeyDataGetPrivateKey(data);
}

static int
xmlSecGCryptKeyDataDsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataDsaId), -1);

    return(xmlSecGCryptAsymKeyDataInitialize(data));
}

static int
xmlSecGCryptKeyDataDsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecGCryptKeyDataDsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecGCryptKeyDataDsaId), -1);

    return(xmlSecGCryptAsymKeyDataDuplicate(dst, src));
}

static void
xmlSecGCryptKeyDataDsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataDsaId));

    xmlSecGCryptAsymKeyDataFinalize(data);
}

static int
xmlSecGCryptKeyDataDsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataDsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    return xmlSecGCryptAsymKeyDataGenerate(data, "dsa", sizeBits);
}

static xmlSecKeyDataType
xmlSecGCryptKeyDataDsaGetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataDsaId), xmlSecKeyDataTypeUnknown);

    return xmlSecGCryptAsymKeyDataGetType(data);
}

static xmlSecSize
xmlSecGCryptKeyDataDsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataDsaId), 0);

    return xmlSecGCryptAsymKeyDataGetSize(data);
}

static void
xmlSecGCryptKeyDataDsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataDsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== dsa key: size = " XMLSEC_SIZE_FMT "\n",
            xmlSecGCryptKeyDataDsaGetSize(data));
}

static void
xmlSecGCryptKeyDataDsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataDsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<DSAKeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
            xmlSecGCryptKeyDataDsaGetSize(data));
}

static int
xmlSecGCryptKeyDataDsaXmlRead(xmlSecKeyDataId id,
                              xmlSecKeyPtr key,
                              xmlNodePtr node,
                              xmlSecKeyInfoCtxPtr keyInfoCtx)
{
    xmlSecAssert2(id == xmlSecGCryptKeyDataDsaId, -1);
    return(xmlSecKeyDataDsaXmlRead(id, key, node, keyInfoCtx,
        xmlSecGCryptKeyDataDsaRead));
}

static int
xmlSecGCryptKeyDataDsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecGCryptKeyDataDsaId, -1);
    return(xmlSecKeyDataDsaXmlWrite(id, key, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecGCryptKeyDataDsaWrite));
}

static int
xmlSecGCryptKeyDataDsaReadMpi(xmlSecBufferPtr buf, gcry_mpi_t* mpi) {
    const xmlSecByte* data;
    xmlSecSize size;
    gpg_error_t err;

    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(mpi != NULL, -1);

    data = xmlSecBufferGetData(buf);
    size = xmlSecBufferGetSize(buf);
    if((data == NULL) || (size == 0)) {
        xmlSecInvalidZeroKeyDataSizeError(NULL);
        return(-1);
    }
    err = gcry_mpi_scan(mpi, GCRYMPI_FMT_USG, data, size, NULL);
    if((err != GPG_ERR_NO_ERROR) || (*mpi == NULL)) {
        xmlSecGCryptError("gcry_mpi_scan", err, NULL);
        return(-1);
    }

    /* success */
    return(0);
}

static xmlSecKeyDataPtr
xmlSecGCryptKeyDataDsaRead(xmlSecKeyDataId id, xmlSecKeyValueDsaPtr dsaValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    gcry_mpi_t p = NULL;
    gcry_mpi_t q = NULL;
    gcry_mpi_t g = NULL;
    gcry_mpi_t x = NULL;
    gcry_mpi_t y = NULL;
    gcry_sexp_t pub_key = NULL;
    gcry_sexp_t priv_key = NULL;
    gcry_error_t err;
    int ret;

    xmlSecAssert2(id == xmlSecGCryptKeyDataDsaId, NULL);
    xmlSecAssert2(dsaValue != NULL, NULL);

    /* p */
    ret = xmlSecGCryptKeyDataDsaReadMpi(&(dsaValue->p), &p);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptKeyDataDsaReadMpi(p)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* q */
    ret = xmlSecGCryptKeyDataDsaReadMpi(&(dsaValue->q), &q);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptKeyDataDsaReadMpi(q)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* g */
    ret = xmlSecGCryptKeyDataDsaReadMpi(&(dsaValue->g), &g);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptKeyDataDsaReadMpi(g)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* x (only for private key) */
    if(!xmlSecBufferIsEmpty(&(dsaValue->x))) {
        ret = xmlSecGCryptKeyDataDsaReadMpi(&(dsaValue->x), &x);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGCryptKeyDataDsaReadMpi(x)", xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    }

    /* y */
    ret = xmlSecGCryptKeyDataDsaReadMpi(&(dsaValue->y), &y);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptKeyDataDsaReadMpi(y)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* construct pub/priv key pairs */
    err = gcry_sexp_build(&pub_key, NULL,
             "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
             p, q, g, y);
    if((err != GPG_ERR_NO_ERROR) || (pub_key == NULL)) {
        xmlSecGCryptError("gcry_sexp_build(public)", err,
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(x != NULL) {
        err = gcry_sexp_build(&priv_key, NULL,
                 "(private-key(dsa(p%m)(q%m)(g%m)(x%m)(y%m)))",
                 p, q, g, x, y);
        if((err != GPG_ERR_NO_ERROR) || (priv_key == NULL)) {
            xmlSecGCryptError("gcry_sexp_build(private)", err,
                xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    }

    /* create key data */
    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
        xmlSecInternalError("xmlSecKeyDataCreate",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecGCryptKeyDataDsaAdoptKeyPair(data, pub_key, priv_key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptKeyDataDsaAdoptKeyPair",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    pub_key = NULL; /* pub_key is owned by data now */
    priv_key = NULL; /* priv_key is owned by data now */

    /* success */
    res = data;
    data = NULL;

done:
    /* cleanup */
    if(p != NULL) {
        gcry_mpi_release(p);
    }

    if(q != NULL) {
        gcry_mpi_release(q);
    }

    if(g != NULL) {
        gcry_mpi_release(g);
    }

    if(x != NULL) {
        gcry_mpi_release(x);
    }

    if(y != NULL) {
        gcry_mpi_release(y);
    }

    if(pub_key != NULL) {
        gcry_sexp_release(pub_key);
    }

    if(priv_key != NULL) {
        gcry_sexp_release(priv_key);
    }

    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

static int
xmlSecGCryptKeyDataDsaWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data,
                            xmlSecKeyValueDsaPtr dsaValue, int writePrivateKey) {
    gcry_sexp_t pub_priv_key;
    gcry_sexp_t dsa = NULL;
    int private = 0;
    int res = -1;
    int ret;

    xmlSecAssert2(id == xmlSecGCryptKeyDataDsaId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataDsaId), -1);
    xmlSecAssert2(dsaValue != NULL, -1);

    /* find the private or public key */
    pub_priv_key = xmlSecGCryptKeyDataDsaGetPrivateKey(data);
    if(pub_priv_key == NULL) {
        pub_priv_key = xmlSecGCryptKeyDataDsaGetPublicKey(data);
        if(pub_priv_key == NULL) {
            xmlSecInternalError("xmlSecGCryptKeyDataDsaGetPublicKey()",
                                xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    } else {
        private = 1;
    }

    dsa = gcry_sexp_find_token(pub_priv_key, "dsa", 0);
    if(dsa == NULL) {
        xmlSecGCryptError("gcry_sexp_find_token(dsa)", (gcry_error_t)GPG_ERR_NO_ERROR,
                          xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* p */
    ret = xmlSecGCryptSetSExpTokValue(dsa, "p", &(dsaValue->p));
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptSetSExpTokValue(p)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* q */
    ret = xmlSecGCryptSetSExpTokValue(dsa, "q", &(dsaValue->q));
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptSetSExpTokValue(q)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* g */
    ret = xmlSecGCryptSetSExpTokValue(dsa, "g", &(dsaValue->g));
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptSetSExpTokValue(g)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* x (only if available and requested) */
    if((writePrivateKey != 0) && (private != 0)) {
        ret = xmlSecGCryptSetSExpTokValue(dsa, "x", &(dsaValue->x));
        if(ret < 0) {
            xmlSecInternalError("xmlSecGCryptSetSExpTokValue(x)",
                                xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    }

    /* y */
    ret = xmlSecGCryptSetSExpTokValue(dsa, "y", &(dsaValue->y));
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptSetSExpTokValue(y)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* success */
    res = 0;

done:
    if(dsa != NULL) {
        gcry_sexp_release(dsa);
    }
    return(res);
}


#endif /* XMLSEC_NO_DSA */


#ifndef XMLSEC_NO_RSA
/******************************************************************************
 *
 * &lt;dsig:RSAKeyValue/&gt; processing
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
  *****************************************************************************/

static int              xmlSecGCryptKeyDataRsaInitialize       (xmlSecKeyDataPtr data);
static int              xmlSecGCryptKeyDataRsaDuplicate        (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
static void             xmlSecGCryptKeyDataRsaFinalize         (xmlSecKeyDataPtr data);
static int              xmlSecGCryptKeyDataRsaXmlRead          (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecGCryptKeyDataRsaXmlWrite         (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecGCryptKeyDataRsaGenerate         (xmlSecKeyDataPtr data,
                                                                 xmlSecSize sizeBits,
                                                                 xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecGCryptKeyDataRsaGetType         (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecGCryptKeyDataRsaGetSize          (xmlSecKeyDataPtr data);
static void             xmlSecGCryptKeyDataRsaDebugDump        (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecGCryptKeyDataRsaDebugXmlDump     (xmlSecKeyDataPtr data,
                                                                 FILE* output);

static xmlSecKeyDataPtr xmlSecGCryptKeyDataRsaRead              (xmlSecKeyDataId id,
                                                                 xmlSecKeyValueRsaPtr rsaValue);
static int              xmlSecGCryptKeyDataRsaWrite             (xmlSecKeyDataId id,
                                                                 xmlSecKeyDataPtr data,
                                                                 xmlSecKeyValueRsaPtr rsaValue,
                                                                 int writePrivateKey);

static xmlSecKeyDataKlass xmlSecGCryptKeyDataRsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecGCryptAsymKeyDataSize,

    /* data */
    xmlSecNameRSAKeyValue,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefRSAKeyValue,                      /* const xmlChar* href; */
    xmlSecNodeRSAKeyValue,                      /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecGCryptKeyDataRsaInitialize,          /* xmlSecKeyDataInitMethod initialize; */
    xmlSecGCryptKeyDataRsaDuplicate,           /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecGCryptKeyDataRsaFinalize,            /* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecGCryptKeyDataRsaGenerate,            /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecGCryptKeyDataRsaGetType,             /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecGCryptKeyDataRsaGetSize,             /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* DEPRECATED xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecGCryptKeyDataRsaXmlRead,             /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecGCryptKeyDataRsaXmlWrite,            /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecGCryptKeyDataRsaDebugDump,           /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecGCryptKeyDataRsaDebugXmlDump,        /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * @brief The GCrypt RSA key data klass.
 * @return pointer to GCrypt RSA key data klass.
 */
xmlSecKeyDataId
xmlSecGCryptKeyDataRsaGetKlass(void) {
    return(&xmlSecGCryptKeyDataRsaKlass);
}

/**
 * @brief Sets the value of RSA key data.
 * @details On success, @p rsa_key will be owned by the @p data; on failure the
 * caller retains ownership.
 * @param data the pointer to RSA key data.
 * @param rsa_key the pointer to GCrypt RSA key.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptKeyDataRsaAdoptKey(xmlSecKeyDataPtr data, gcry_sexp_t rsa_key) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataRsaId), -1);
    xmlSecAssert2(rsa_key != NULL, -1);

    if(xmlSecGCryptAsymKeyDataCheckKeyAlg(rsa_key, "rsa") < 0) {
        xmlSecInvalidDataError("the provided key is not an RSA key", xmlSecKeyDataGetName(data));
        return(-1);
    }

    return xmlSecGCryptAsymKeyDataAdoptKey(data, rsa_key);
}


/**
 * @brief Sets the value of RSA key data.
 * @details On success, @p pub_key and @p priv_key will be owned by the @p data;
 * on failure the caller retains ownership.
 * @param data the pointer to RSA key data.
 * @param pub_key the pointer to GCrypt RSA pub key.
 * @param priv_key the pointer to GCrypt RSA priv key.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptKeyDataRsaAdoptKeyPair(xmlSecKeyDataPtr data, gcry_sexp_t pub_key, gcry_sexp_t priv_key) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataRsaId), -1);
    xmlSecAssert2(pub_key != NULL, -1);

    if(xmlSecGCryptAsymKeyDataCheckKeyAlg(pub_key, "rsa") < 0) {
        xmlSecInvalidDataError("the provided key is not an RSA key", xmlSecKeyDataGetName(data));
        return(-1);
    }
    if((priv_key != NULL) && (xmlSecGCryptAsymKeyDataCheckKeyAlg(priv_key, "rsa") < 0)) {
        xmlSecInvalidDataError("the provided key is not an RSA key", xmlSecKeyDataGetName(data));
        return(-1);
    }

    return xmlSecGCryptAsymKeyDataAdoptKeyPair(data, pub_key, priv_key);
}

/**
 * @brief Gets the GCrypt RSA public key from RSA key data.
 * @param data the pointer to RSA key data.
 * @return pointer to GCrypt public RSA key or NULL if an error occurs.
 */
gcry_sexp_t
xmlSecGCryptKeyDataRsaGetPublicKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataRsaId), NULL);
    return xmlSecGCryptAsymKeyDataGetPublicKey(data);
}

/**
 * @brief Gets the GCrypt RSA private key from RSA key data.
 * @param data the pointer to RSA key data.
 * @return pointer to GCrypt private RSA key or NULL if an error occurs.
 */
gcry_sexp_t
xmlSecGCryptKeyDataRsaGetPrivateKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataRsaId), NULL);
    return xmlSecGCryptAsymKeyDataGetPrivateKey(data);
}

static int
xmlSecGCryptKeyDataRsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataRsaId), -1);

    return(xmlSecGCryptAsymKeyDataInitialize(data));
}

static int
xmlSecGCryptKeyDataRsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecGCryptKeyDataRsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecGCryptKeyDataRsaId), -1);

    return(xmlSecGCryptAsymKeyDataDuplicate(dst, src));
}

static void
xmlSecGCryptKeyDataRsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataRsaId));

    xmlSecGCryptAsymKeyDataFinalize(data);
}

static int
xmlSecGCryptKeyDataRsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataRsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    return xmlSecGCryptAsymKeyDataGenerate(data, "rsa", sizeBits);
}

static xmlSecKeyDataType
xmlSecGCryptKeyDataRsaGetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataRsaId), xmlSecKeyDataTypeUnknown);

    return xmlSecGCryptAsymKeyDataGetType(data);
}

static xmlSecSize
xmlSecGCryptKeyDataRsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataRsaId), 0);

    return xmlSecGCryptAsymKeyDataGetSize(data);
}

static void
xmlSecGCryptKeyDataRsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== rsa key: size = " XMLSEC_SIZE_FMT "\n",
            xmlSecGCryptKeyDataRsaGetSize(data));
}

static void
xmlSecGCryptKeyDataRsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<RSAKeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
            xmlSecGCryptKeyDataRsaGetSize(data));
}

static int
xmlSecGCryptKeyDataRsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                              xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecGCryptKeyDataRsaId, -1);
    return(xmlSecKeyDataRsaXmlRead(id, key, node, keyInfoCtx, xmlSecGCryptKeyDataRsaRead));
}

static int
xmlSecGCryptKeyDataRsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                            xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecGCryptKeyDataRsaId, -1);
    return(xmlSecKeyDataRsaXmlWrite(id, key, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecGCryptKeyDataRsaWrite));
}

static xmlSecKeyDataPtr
xmlSecGCryptKeyDataRsaRead(xmlSecKeyDataId id, xmlSecKeyValueRsaPtr rsaValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    gcry_mpi_t modulus = NULL;
    gcry_mpi_t publicExponent = NULL;
    gcry_mpi_t privateExponent = NULL;
    gcry_sexp_t pub_key = NULL;
    gcry_sexp_t priv_key = NULL;
    gcry_error_t err;
    int ret;

    xmlSecAssert2(id == xmlSecGCryptKeyDataRsaId, NULL);
    xmlSecAssert2(rsaValue != NULL, NULL);

    /* Modulus */
    if(xmlSecBufferGetSize(&(rsaValue->modulus)) == 0) {
        xmlSecInvalidZeroKeyDataSizeError(xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    err = gcry_mpi_scan(&modulus, GCRYMPI_FMT_USG,
        xmlSecBufferGetData(&(rsaValue->modulus)),
        xmlSecBufferGetSize(&(rsaValue->modulus)),
        NULL);
    if((err != GPG_ERR_NO_ERROR) || (modulus == NULL)) {
        xmlSecGCryptError("gcry_mpi_scan(Modulus)", err,
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* Exponent */
    if(xmlSecBufferGetSize(&(rsaValue->publicExponent)) == 0) {
        xmlSecInvalidZeroKeyDataSizeError(xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    err = gcry_mpi_scan(&publicExponent, GCRYMPI_FMT_USG,
        xmlSecBufferGetData(&(rsaValue->publicExponent)),
        xmlSecBufferGetSize(&(rsaValue->publicExponent)),
        NULL);
    if((err != GPG_ERR_NO_ERROR) || (publicExponent == NULL)) {
        xmlSecGCryptError("gcry_mpi_scan(Exponent)", err,
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* PrivateExponent (only for private key) */
    if(xmlSecBufferGetSize(&(rsaValue->privateExponent)) > 0) {
        err = gcry_mpi_scan(&privateExponent, GCRYMPI_FMT_USG,
            xmlSecBufferGetData(&(rsaValue->privateExponent)),
            xmlSecBufferGetSize(&(rsaValue->privateExponent)),
            NULL);
        if((err != GPG_ERR_NO_ERROR) || (privateExponent == NULL)) {
            xmlSecGCryptError("gcry_mpi_scan(PrivateExponent)", err,
                xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    }

    /* construct pub/priv key pairs */
    err = gcry_sexp_build(&pub_key, NULL,
             "(public-key(rsa(n%m)(e%m)))",
             modulus, publicExponent);
    if((err != GPG_ERR_NO_ERROR) || (pub_key == NULL)) {
        xmlSecGCryptError("gcry_sexp_build(public)", err,
                          xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    if(privateExponent != NULL) {
        err = gcry_sexp_build(&priv_key, NULL,
                  "(private-key(rsa(n%m)(e%m)(d%m)))",
                  modulus, publicExponent, privateExponent);
        if((err != GPG_ERR_NO_ERROR) || (priv_key == NULL)) {
            xmlSecGCryptError("gcry_sexp_build(private)", err,
                              xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    }

    /* create key data */
    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
        xmlSecInternalError("xmlSecKeyDataCreate",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecGCryptKeyDataRsaAdoptKeyPair(data, pub_key, priv_key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptKeyDataRsaAdoptKeyPair",
                            xmlSecKeyDataGetName(data));
        goto done;
    }
    pub_key = NULL; /* pub_key is owned by data now */
    priv_key = NULL; /* priv_key is owned by data now */

    /* success */
    res = data;
    data = NULL;

done:
    /* cleanup */
    if(modulus != NULL) {
        gcry_mpi_release(modulus);
    }

    if(publicExponent != NULL) {
        gcry_mpi_release(publicExponent);
    }

    if(privateExponent != NULL) {
        gcry_mpi_release(privateExponent);
    }

    if(pub_key != NULL) {
        gcry_sexp_release(pub_key);
    }

    if(priv_key != NULL) {
        gcry_sexp_release(priv_key);
    }

    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

static int
xmlSecGCryptKeyDataRsaWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data,
                            xmlSecKeyValueRsaPtr rsaValue, int writePrivateKey) {
    gcry_sexp_t pub_priv_key;
    gcry_sexp_t rsa = NULL;
    int private = 0;
    int res = -1;
    int ret;

    xmlSecAssert2(id == xmlSecGCryptKeyDataRsaId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataRsaId), -1);
    xmlSecAssert2(rsaValue != NULL, -1);

    /* find the private or public key */
    pub_priv_key = xmlSecGCryptKeyDataRsaGetPrivateKey(data);
    if(pub_priv_key == NULL) {
        pub_priv_key = xmlSecGCryptKeyDataRsaGetPublicKey(data);
        if(pub_priv_key == NULL) {
            xmlSecInternalError("xmlSecGCryptKeyDataRsaGetPublicKey()",
                                xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    } else {
        private = 1;
    }

    rsa = gcry_sexp_find_token(pub_priv_key, "rsa", 0);
    if(rsa == NULL) {
        xmlSecGCryptError("gcry_sexp_find_token(rsa)", (gcry_error_t)GPG_ERR_NO_ERROR,
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* Modulus */
    ret = xmlSecGCryptSetSExpTokValue(rsa, "n", &(rsaValue->modulus));
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptSetSExpTokValue(Modulus)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* Exponent */
    ret = xmlSecGCryptSetSExpTokValue(rsa, "e", &(rsaValue->publicExponent));
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptSetSExpTokValue(Exponent)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* PrivateExponent (only if available and requested) */
    if((writePrivateKey != 0) && (private != 0)) {
        ret = xmlSecGCryptSetSExpTokValue(rsa, "d", &(rsaValue->privateExponent));
        if(ret < 0) {
            xmlSecInternalError("xmlSecGCryptSetSExpTokValue(PrivateExponent)",
                                xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    }

    /* success */
    res = 0;

done:
    if(rsa != NULL) {
        gcry_sexp_release(rsa);
    }

    return(res);
}
#endif /* XMLSEC_NO_RSA */



#ifndef XMLSEC_NO_EC
/******************************************************************************
 *
 * EC Keys.
 *
  *****************************************************************************/

static int              xmlSecGCryptKeyDataEcInitialize         (xmlSecKeyDataPtr data);
static int              xmlSecGCryptKeyDataEcDuplicate          (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
static void             xmlSecGCryptKeyDataEcFinalize           (xmlSecKeyDataPtr data);

static xmlSecKeyDataType xmlSecGCryptKeyDataEcGetType           (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecGCryptKeyDataEcGetSize            (xmlSecKeyDataPtr data);
static void             xmlSecGCryptKeyDataEcDebugDump          (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecGCryptKeyDataEcDebugXmlDump       (xmlSecKeyDataPtr data,
                                                                 FILE* output);

static int              xmlSecGCryptKeyDataEcXmlRead            (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecGCryptKeyDataEcXmlWrite           (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyDataPtr xmlSecGCryptKeyDataEcRead               (xmlSecKeyDataId id,
                                                                 xmlSecKeyValueEcPtr ecValue);
static int              xmlSecGCryptKeyDataEcWrite              (xmlSecKeyDataId id,
                                                                 xmlSecKeyDataPtr data,
                                                                 xmlSecKeyValueEcPtr ecValue);

static xmlSecKeyDataKlass xmlSecGCryptKeyDataEcKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecGCryptAsymKeyDataSize,

    /* data */
    xmlSecNameECKeyValue,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefECKeyValue,                       /* const xmlChar* href; */
    xmlSecNodeECKeyValue,                       /* const xmlChar* dataNodeName; */
    xmlSecDSig11Ns,                             /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecGCryptKeyDataEcInitialize,            /* xmlSecKeyDataInitMethod initialize; */
    xmlSecGCryptKeyDataEcDuplicate,             /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecGCryptKeyDataEcFinalize,              /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecGCryptKeyDataEcGetType,               /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecGCryptKeyDataEcGetSize,               /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* DEPRECATED xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecGCryptKeyDataEcXmlRead,               /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecGCryptKeyDataEcXmlWrite,              /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecGCryptKeyDataEcDebugDump,             /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecGCryptKeyDataEcDebugXmlDump,          /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * @brief The GCrypt EC key data klass.
 * @return pointer to GCrypt EC key data klass.
 */
xmlSecKeyDataId
xmlSecGCryptKeyDataEcGetKlass(void) {
    return(&xmlSecGCryptKeyDataEcKlass);
}

/**
 * @brief Checks that a GCrypt key S-expression is an EC key.
 * @details Accepts both the "ecdsa" and the "ecc" algorithm token: "ecdsa" is
 * the token used in the S-expressions constructed by this back-end, while "ecc"
 * is the token that libgcrypt itself uses in the EC keys it creates
 * (e.g. with gcry_pk_genkey).
 * @param key the pointer to the GCrypt key S-expression (public key, private key, or key pair).
 * @return 0 if the key is an EC key or -1 otherwise.
 */
static int
xmlSecGCryptKeyDataEcCheckKeyAlg(gcry_sexp_t key) {
    gcry_sexp_t tok;

    xmlSecAssert2(key != NULL, -1);

    /* the algorithm token (ecdsa/ecc) is present in the public-key,
       private-key and key-pair S-expressions alike, so its presence
       unambiguously identifies the key type */
    tok = gcry_sexp_find_token(key, "ecdsa", 0);
    if(tok == NULL) {
        tok = gcry_sexp_find_token(key, "ecc", 0);
    }
    if(tok == NULL) {
        return(-1);
    }
    gcry_sexp_release(tok);

    /* success */
    return(0);
}

/**
 * @brief Sets the value of EC key data.
 * @details On success, @p ec_key will be owned by the @p data; on failure the
 * caller retains ownership.
 * @param data the pointer to EC key data.
 * @param ec_key the pointer to GCrypt EC key.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptKeyDataEcAdoptKey(xmlSecKeyDataPtr data, gcry_sexp_t ec_key) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataEcId), -1);
    xmlSecAssert2(ec_key != NULL, -1);

    if(xmlSecGCryptKeyDataEcCheckKeyAlg(ec_key) < 0) {
        xmlSecInvalidDataError("the provided key is not an EC key", xmlSecKeyDataGetName(data));
        return(-1);
    }

    return(xmlSecGCryptAsymKeyDataAdoptKey(data, ec_key));
}

/**
 * @brief Sets the value of EC key data.
 * @details On success, @p pub_key and @p priv_key will be owned by the @p data;
 * on failure the caller retains ownership.
 * @param data the pointer to EC key data.
 * @param pub_key the pointer to GCrypt EC pub key.
 * @param priv_key the pointer to GCrypt EC priv key.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptKeyDataEcAdoptKeyPair(xmlSecKeyDataPtr data, gcry_sexp_t pub_key, gcry_sexp_t priv_key) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataEcId), -1);
    xmlSecAssert2(pub_key != NULL, -1);

    if(xmlSecGCryptKeyDataEcCheckKeyAlg(pub_key) < 0) {
        xmlSecInvalidDataError("the provided key is not an EC key", xmlSecKeyDataGetName(data));
        return(-1);
    }
    if((priv_key != NULL) && (xmlSecGCryptKeyDataEcCheckKeyAlg(priv_key) < 0)) {
        xmlSecInvalidDataError("the provided key is not an EC key", xmlSecKeyDataGetName(data));
        return(-1);
    }

    return(xmlSecGCryptAsymKeyDataAdoptKeyPair(data, pub_key, priv_key));
}

/**
 * @brief Gets the GCrypt EC public key from EC key data.
 * @param data the pointer to EC key data.
 * @return pointer to GCrypt public EC key or NULL if an error occurs.
 */
gcry_sexp_t
xmlSecGCryptKeyDataEcGetPublicKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataEcId), NULL);
    return(xmlSecGCryptAsymKeyDataGetPublicKey(data));
}

/**
 * @brief Gets the GCrypt EC private key from EC key data.
 * @param data the pointer to EC key data.
 * @return pointer to GCrypt private EC key or NULL if an error occurs.
 */
gcry_sexp_t
xmlSecGCryptKeyDataEcGetPrivateKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataEcId), NULL);
    return(xmlSecGCryptAsymKeyDataGetPrivateKey(data));
}

static int
xmlSecGCryptKeyDataEcInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataEcId), -1);

    return(xmlSecGCryptAsymKeyDataInitialize(data));
}

static int
xmlSecGCryptKeyDataEcDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecGCryptKeyDataEcId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecGCryptKeyDataEcId), -1);

    return(xmlSecGCryptAsymKeyDataDuplicate(dst, src));
}

static void
xmlSecGCryptKeyDataEcFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataEcId));

    xmlSecGCryptAsymKeyDataFinalize(data);
}

static xmlSecKeyDataType
xmlSecGCryptKeyDataEcGetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataEcId), xmlSecKeyDataTypeUnknown);

    return xmlSecGCryptAsymKeyDataGetType(data);
}

static xmlSecSize
xmlSecGCryptKeyDataEcGetSize(xmlSecKeyDataPtr data) {
    xmlSecGCryptAsymKeyDataCtxPtr ctx;
    gcry_sexp_t key;
    unsigned int nbits = 0;
    const char *curve;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataEcId), 0);

    ctx = xmlSecGCryptAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    if(ctx->priv_key != NULL) {
        key = ctx->priv_key;
    } else if(ctx->pub_key != NULL) {
        key = ctx->pub_key;
    } else {
        return(0);
    }

    curve = gcry_pk_get_curve(key, 0, &nbits);
    XMLSEC_UNREFERENCED(curve);
    return(nbits);
}

static void
xmlSecGCryptKeyDataEcDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataEcId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== ec key: size = " XMLSEC_SIZE_FMT "\n",
            xmlSecGCryptKeyDataEcGetSize(data));
}

static void
xmlSecGCryptKeyDataEcDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataEcId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<ECKeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
            xmlSecGCryptKeyDataEcGetSize(data));
}

static int
xmlSecGCryptKeyDataEcXmlRead(xmlSecKeyDataId id,
                              xmlSecKeyPtr key,
                              xmlNodePtr node,
                              xmlSecKeyInfoCtxPtr keyInfoCtx)
{
    xmlSecAssert2(id == xmlSecGCryptKeyDataEcId, -1);
    return(xmlSecKeyDataEcXmlRead(id, key, node, keyInfoCtx,
        xmlSecGCryptKeyDataEcRead));
}

static int
xmlSecGCryptKeyDataEcXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecGCryptKeyDataEcId, -1);
    return(xmlSecKeyDataEcXmlWrite(id, key, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecGCryptKeyDataEcWrite));
}


typedef struct _xmlSecGCryptKeyDataEcCurveOidToName {
    char curveName[20];
    xmlChar curveOid[64];
} xmlSecGCryptKeyDataEcCurveOidToName;

/* The table contains both the curve names accepted by libgcrypt in the
   S-expressions (secpNnnr1, primeNnnv1, secp256k1, brainpoolPNNNr1) and the
   canonical names that libgcrypt itself stores in the S-expressions of the
   keys it creates (e.g. "NIST P-256" for secp256r1/prime256v1), so that both
   the keys constructed by this back-end and the libgcrypt-created keys can be
   written to XML. */
static xmlSecGCryptKeyDataEcCurveOidToName g_xmlSecGCryptKeyDataEcCurveOidToName[] = {
    { "prime192v1",      "1.2.840.10045.3.1.1" },
    { "prime256v1",      "1.2.840.10045.3.1.7" },
    { "secp192r1",       "1.3.132.0.32" },
    { "secp224r1",       "1.3.132.0.33" },
    { "secp256r1",       "1.2.840.10045.3.1.7" },
    { "secp384r1",       "1.3.132.0.34" },
    { "secp521r1",       "1.3.132.0.35" },
    { "secp256k1",       "1.3.132.0.10" },
    { "brainpoolP160r1", "1.3.36.3.3.2.8.1.1.1" },
    { "brainpoolP192r1", "1.3.36.3.3.2.8.1.1.3" },
    { "brainpoolP224r1", "1.3.36.3.3.2.8.1.1.5" },
    { "brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7" },
    { "brainpoolP320r1", "1.3.36.3.3.2.8.1.1.9" },
    { "brainpoolP384r1", "1.3.36.3.3.2.8.1.1.11" },
    { "brainpoolP512r1", "1.3.36.3.3.2.8.1.1.13" },
    { "NIST P-192",      "1.2.840.10045.3.1.1" },
    { "NIST P-224",      "1.3.132.0.33" },
    { "NIST P-256",      "1.2.840.10045.3.1.7" },
    { "NIST P-384",      "1.3.132.0.34" },
    { "NIST P-521",      "1.3.132.0.35" }
};

static const char*
xmlSecGCryptKeyDataEcCurveGetNameFromOid(const xmlChar * curveOid) {
    xmlSecSize size = sizeof(g_xmlSecGCryptKeyDataEcCurveOidToName) / sizeof(g_xmlSecGCryptKeyDataEcCurveOidToName[0]);

    xmlSecAssert2(curveOid != NULL, NULL);
    for(xmlSecSize ii = 0; ii < size; ++ii) {
        if(xmlStrcmp(curveOid, g_xmlSecGCryptKeyDataEcCurveOidToName[ii].curveOid) == 0) {
            return(g_xmlSecGCryptKeyDataEcCurveOidToName[ii].curveName);
        }
    }
    return(NULL);
}

static const xmlChar*
xmlSecGCryptKeyDataEcCurveGetOidFromName(const char * curveName) {
    xmlSecSize size = sizeof(g_xmlSecGCryptKeyDataEcCurveOidToName) / sizeof(g_xmlSecGCryptKeyDataEcCurveOidToName[0]);

    xmlSecAssert2(curveName != NULL, NULL);
    for(xmlSecSize ii = 0; ii < size; ++ii) {
        if(strcmp(curveName, g_xmlSecGCryptKeyDataEcCurveOidToName[ii].curveName) == 0) {
            return(g_xmlSecGCryptKeyDataEcCurveOidToName[ii].curveOid);
        }
    }
    return(NULL);
}

static xmlSecKeyDataPtr
xmlSecGCryptKeyDataEcRead(xmlSecKeyDataId id, xmlSecKeyValueEcPtr ecValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    gcry_mpi_t pubkey = NULL;
    gcry_sexp_t s_pub_key = NULL;
    gcry_error_t err;
    const char* curveName;
    int ret;

    xmlSecAssert2(id == xmlSecGCryptKeyDataEcId, NULL);
    xmlSecAssert2(ecValue != NULL, NULL);
    xmlSecAssert2(ecValue->curve != NULL, NULL);

    /* get curve name */
    curveName = xmlSecGCryptKeyDataEcCurveGetNameFromOid(ecValue->curve);
    if(curveName == NULL) {
        xmlSecInternalError2("xmlSecGCryptKeyDataEcCurveGetNameFromOid", xmlSecKeyDataKlassGetName(id),
            "curveOid=%s", xmlSecErrorsSafeString(ecValue->curve));
        goto done;
    }

    /* check that the public key point is well-formed (odd size > 1 and the
       leading uncompressed point magic byte 0x04); note that the point cannot
       be validated to be on the curve, because libgcrypt does not expose the
       curve parameters for that */
    ret = xmlSecKeyDataEcPublicKeySplitComponents(ecValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyDataEcPublicKeySplitComponents", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* pubkey */
    err = gcry_mpi_scan(&pubkey, GCRYMPI_FMT_USG,
        xmlSecBufferGetData(&(ecValue->pubkey)), xmlSecBufferGetSize(&(ecValue->pubkey)),
        NULL);
    if((err != GPG_ERR_NO_ERROR) || (pubkey == NULL)) {
        xmlSecGCryptError("gcry_mpi_scan(pubkey)", err, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* construct pub key */
    err = gcry_sexp_build (&s_pub_key, NULL,
        "(public-key"
        " (ecdsa"
        " (curve %s)"
        " (q %m)"
        " ))",
        curveName, pubkey
    );
    if((err != GPG_ERR_NO_ERROR) || (s_pub_key == NULL)) {
        xmlSecGCryptError("gcry_sexp_build(public)", err, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* create key data */
    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
        xmlSecInternalError("xmlSecKeyDataCreate", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecGCryptKeyDataEcAdoptKeyPair(data, s_pub_key, NULL);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptKeyDataEcAdoptKeyPair", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    s_pub_key = NULL; /* pub_key is owned by data now */

    /* success */
    res = data;
    data = NULL;

done:
    /* cleanup */
    if(pubkey != NULL) {
        gcry_mpi_release(pubkey);
    }
    if(s_pub_key != NULL) {
        gcry_sexp_release(s_pub_key);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

/* use gcry_free() to deallocate returned string */
static char*
xmlSecGCryptGetStringFromSExp(const gcry_sexp_t sexp, const char * tok)
{
    gcry_sexp_t val = NULL;
    char* res = NULL;

    xmlSecAssert2(sexp != NULL, NULL);
    xmlSecAssert2(tok != NULL, NULL);

    val = gcry_sexp_find_token(sexp, tok, 0);
    if(val == NULL) {
        xmlSecGCryptError2("gcry_sexp_find_token", (gcry_error_t)GPG_ERR_NO_ERROR, NULL,
            "tok=%s", xmlSecErrorsSafeString(tok));
        goto done;
    }

    res = gcry_sexp_nth_string(val, 1);
    if(res == NULL) {
        xmlSecGCryptError2("gcry_sexp_nth_string", (gcry_error_t)GPG_ERR_NO_ERROR, NULL,
            "tok=%s", xmlSecErrorsSafeString(tok));
        goto done;
    }

done:
    if(val != NULL) {
        gcry_sexp_release(val);
    }
    return(res);
}


static int
xmlSecGCryptKeyDataEcWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data, xmlSecKeyValueEcPtr ecValue) {
    gcry_sexp_t s_pub_key;
    gcry_sexp_t s_ecdsa = NULL;
    char* curveName = NULL;
    const xmlChar* curveOid;
    int res = -1;
    int ret;

    xmlSecAssert2(id == xmlSecGCryptKeyDataEcId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGCryptKeyDataEcId), -1);
    xmlSecAssert2(ecValue != NULL, -1);

    /* find the private or public key */
    s_pub_key = xmlSecGCryptKeyDataEcGetPublicKey(data);
    if(s_pub_key == NULL) {
        xmlSecInternalError("xmlSecGCryptKeyDataEcGetPublicKey()", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* the algorithm token is "ecdsa" for the S-expressions constructed by this
       back-end and "ecc" for the keys created by libgcrypt itself */
    s_ecdsa = gcry_sexp_find_token(s_pub_key, "ecdsa", 0);
    if(s_ecdsa == NULL) {
        s_ecdsa = gcry_sexp_find_token(s_pub_key, "ecc", 0);
    }
    if(s_ecdsa == NULL) {
        xmlSecGCryptError("gcry_sexp_find_token(ecdsa/ecc)", (gcry_error_t)GPG_ERR_NO_ERROR,
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* curve */
    curveName = xmlSecGCryptGetStringFromSExp(s_ecdsa,  "curve");
    if(curveName == NULL) {
        xmlSecInternalError("xmlSecGCryptGetStringFromSExp(curve)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    curveOid = xmlSecGCryptKeyDataEcCurveGetOidFromName(curveName);
    if(curveOid == NULL) {
        xmlSecInternalError2("xmlSecGCryptKeyDataEcCurveGetOidFromName", xmlSecKeyDataKlassGetName(id),
            "curveName=%s", xmlSecErrorsSafeString(curveName));
        goto done;
    }
    ecValue->curve = xmlStrdup(curveOid);
    if(ecValue->curve == NULL) {
        xmlSecStrdupError(curveOid, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* pubkey */
    ret = xmlSecGCryptSetSExpTokValue(s_ecdsa, "q", &(ecValue->pubkey));
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptSetSExpTokValue(q)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* success */
    res = 0;

done:
    if(curveName != NULL) {
        gcry_free(curveName);
    }
    if(s_ecdsa != NULL) {
        gcry_sexp_release(s_ecdsa);
    }

    return(res);
}

#endif /* XMLSEC_NO_EC */
