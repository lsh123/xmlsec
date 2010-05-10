/**
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2010 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <gnutls/gnutls.h>
#include <gcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/base64.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gnutls/crypto.h>

/**************************************************************************
 *
 * Helpers
 *
 *************************************************************************/
static gcry_sexp_t              xmlSecGnuTLSAsymSExpDup          (gcry_sexp_t sexp);


/**************************************************************************
 *
 * Internal GnuTLS asym key CTX
 *
 *************************************************************************/
typedef struct _xmlSecGnuTLSAsymKeyDataCtx       xmlSecGnuTLSAsymKeyDataCtx,
                                                *xmlSecGnuTLSAsymKeyDataCtxPtr;
struct _xmlSecGnuTLSAsymKeyDataCtx {
    gcry_sexp_t pub_key;
    gcry_sexp_t priv_key;
};

/******************************************************************************
 *
 * Asym key (dsa/rsa)
 *
 * xmlSecGnuTLSAsymKeyDataCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecGnuTLSAsymKeyDataSize     \
    (sizeof(xmlSecKeyData) + sizeof(xmlSecGnuTLSAsymKeyDataCtx))
#define xmlSecGnuTLSAsymKeyDataGetCtx(data) \
    ((xmlSecGnuTLSAsymKeyDataCtxPtr)(((xmlSecByte*)(data)) + sizeof(xmlSecKeyData)))

static int              xmlSecGnuTLSAsymKeyDataInitialize       (xmlSecKeyDataPtr data);
static int              xmlSecGnuTLSAsymKeyDataDuplicate        (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
static void             xmlSecGnuTLSAsymKeyDataFinalize         (xmlSecKeyDataPtr data);

static int              xmlSecGnuTLSAsymKeyDataAdoptKey         (xmlSecKeyDataPtr data,
                                                                 gcry_sexp_t key_pair);
static int              xmlSecGnuTLSAsymKeyDataAdoptKeyPair     (xmlSecKeyDataPtr data,
                                                                 gcry_sexp_t pub_key,
                                                                 gcry_sexp_t priv_key);
static gcry_sexp_t      xmlSecGnuTLSAsymKeyDataGetPublicKey     (xmlSecKeyDataPtr data);
static gcry_sexp_t      xmlSecGnuTLSAsymKeyDataGetPrivateKey    (xmlSecKeyDataPtr data);
static int              xmlSecGnuTLSAsymKeyDataGenerate         (xmlSecKeyDataPtr data,
                                                                 const char * alg,
                                                                 xmlSecSize key_size);
static xmlSecKeyDataType xmlSecGnuTLSAsymKeyDataGetType         (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecGnuTLSAsymKeyDataGetSize          (xmlSecKeyDataPtr data);


static int
xmlSecGnuTLSAsymKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), -1);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecGnuTLSAsymKeyDataCtx));

    return(0);
}

static int
xmlSecGnuTLSAsymKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctxDst;
    xmlSecGnuTLSAsymKeyDataCtxPtr ctxSrc;

    xmlSecAssert2(xmlSecKeyDataIsValid(dst), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(dst, xmlSecGnuTLSAsymKeyDataSize), -1);
    xmlSecAssert2(xmlSecKeyDataIsValid(src), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(src, xmlSecGnuTLSAsymKeyDataSize), -1);

    ctxDst = xmlSecGnuTLSAsymKeyDataGetCtx(dst);
    xmlSecAssert2(ctxDst != NULL, -1);
    xmlSecAssert2(ctxDst->pub_key == NULL, -1);
    xmlSecAssert2(ctxDst->priv_key == NULL, -1);

    ctxSrc = xmlSecGnuTLSAsymKeyDataGetCtx(src);
    xmlSecAssert2(ctxSrc != NULL, -1);

    if(ctxSrc->pub_key != NULL) {
        ctxDst->pub_key = xmlSecGnuTLSAsymSExpDup(ctxSrc->pub_key);
        if(ctxDst->pub_key == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
                        "xmlSecGnuTLSAsymSExpDup(pub_key)",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    }

    if(ctxSrc->priv_key != NULL) {
        ctxDst->priv_key = xmlSecGnuTLSAsymSExpDup(ctxSrc->priv_key);
        if(ctxDst->priv_key == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataGetName(dst)),
                        "xmlSecGnuTLSAsymSExpDup(priv_key)",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    }

    return(0);
}

static void
xmlSecGnuTLSAsymKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize));

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    if(ctx->pub_key != NULL) {
        gcry_sexp_release(ctx->pub_key);
    }
    if(ctx->priv_key != NULL) {
        gcry_sexp_release(ctx->priv_key);
    }
    memset(ctx, 0, sizeof(xmlSecGnuTLSAsymKeyDataCtx));
}

static int
xmlSecGnuTLSAsymKeyDataAdoptKey(xmlSecKeyDataPtr data, gcry_sexp_t key_pair) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;
    gcry_sexp_t pub_key = NULL;
    gcry_sexp_t priv_key = NULL;
    int res = -1;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), -1);
    xmlSecAssert2(key_pair != NULL, -1);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    /* split the key pair, public part should be always present, private might 
       not be present */
    pub_key = gcry_sexp_find_token(key_pair, "public-key", 0);
    if(pub_key == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_sexp_find_token(public-key)",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }
    priv_key = gcry_sexp_find_token(key_pair, "private-key", 0);

    /* assign */
    if(xmlSecGnuTLSAsymKeyDataAdoptKeyPair(data, pub_key, priv_key) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGnuTLSAsymKeyDataAdoptKeyPair",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }
    pub_key = NULL; /* data owns it now */
    priv_key = NULL; /* data owns it now */

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
xmlSecGnuTLSAsymKeyDataAdoptKeyPair(xmlSecKeyDataPtr data, gcry_sexp_t pub_key, gcry_sexp_t priv_key) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), -1);
    xmlSecAssert2(pub_key != NULL, -1); /* public key should present always */
    xmlSecAssert2(((priv_key == NULL) || (gcry_pk_testkey(priv_key) == GPG_ERR_NO_ERROR)), -1);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
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
xmlSecGnuTLSAsymKeyDataGetPublicKey(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), NULL);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->pub_key);
}

static gcry_sexp_t
xmlSecGnuTLSAsymKeyDataGetPrivateKey(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), NULL);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->priv_key);
}

static int
xmlSecGnuTLSAsymKeyDataGenerate(xmlSecKeyDataPtr data, const char * alg, xmlSecSize key_size) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;
    gcry_sexp_t key_spec = NULL;
    gcry_sexp_t key_pair = NULL;
    gcry_error_t err;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), -1);
    xmlSecAssert2(alg != NULL, -1);
    xmlSecAssert2(key_size > 0, -1);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    err = gcry_sexp_build(&key_spec, NULL,
                          "(genkey (%s (nbits %d)(transient-key)))",
                          alg, (int)key_size);
    if((err != GPG_ERR_NO_ERROR) || (key_spec == NULL)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_sexp_build(genkey)",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    "err=%d", (int)err);
        goto done;
    }

    err = gcry_pk_genkey(&key_pair, key_spec);
    if((err != GPG_ERR_NO_ERROR) || (key_pair == NULL)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_pk_genkey",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    "err=%d", (int)err);
        goto done;
    }

    ret = xmlSecGnuTLSAsymKeyDataAdoptKey(data, key_pair);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGnuTLSAsymKeyDataAdopt",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "ret=%d", (int)ret);
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
xmlSecGnuTLSAsymKeyDataGetType(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, xmlSecKeyDataTypeUnknown);

    if((ctx->priv_key != NULL) && (ctx->pub_key != NULL)) {
        return (xmlSecKeyDataTypePrivate);
    } else if(ctx->pub_key != NULL) {
        return (xmlSecKeyDataTypePublic);
    }

    return (xmlSecKeyDataTypeUnknown);
}

static xmlSecSize
xmlSecGnuTLSAsymKeyDataGetSize(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    /* use pub key since it is more often you have it than not */
    return (ctx->pub_key != NULL) ? gcry_pk_get_nbits(ctx->pub_key) : 0;
}

/******************************************************************************
 *
 * helper functions
 *
 *****************************************************************************/
static gcry_sexp_t
xmlSecGnuTLSAsymSExpDup(gcry_sexp_t pKey) {
    gcry_sexp_t res = NULL;
    xmlSecByte *buf = NULL;
    gcry_error_t ret;
    size_t size;

    xmlSecAssert2(pKey != NULL, NULL);

    size = gcry_sexp_sprint(pKey, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    if(size == 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_sexp_sprint",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }

    buf = (xmlSecByte *)xmlMalloc(size);
    if(buf == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlMalloc",
                    XMLSEC_ERRORS_R_MALLOC_FAILED,
                    "size=%d", (int)size);
        goto done;
    }

    size = gcry_sexp_sprint(pKey, GCRYSEXP_FMT_ADVANCED, buf, size);
    if(size == 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_sexp_sprint",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    "size=%d", (int)size);
        goto done;
    }

    ret = gcry_sexp_new(&res, buf, size, 1);
    if((ret != GPG_ERR_NO_ERROR) || (res == NULL)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_sexp_new",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    "ret=%d", (int)ret);
        goto done;
    }

done:
    if(buf != NULL) {
        xmlFree(buf);
    }
    return (res);
}

/**
 * xmlSecGnuTLSNodeGetMpiValue:
 * @cur: the poitner to an XML node.
 *
 * Converts the node content from CryptoBinary format
 * (http://www.w3.org/TR/xmldsig-core/#sec-CryptoBinary)
 * to a BIGNUM. If no BIGNUM buffer provided then a new
 * BIGNUM is created (caller is responsible for freeing it).
 *
 * Returns: a pointer to MPI produced from CryptoBinary string
 * or NULL if an error occurs.
 */
static gcry_mpi_t
xmlSecGnuTLSNodeGetMpiValue(const xmlNodePtr cur) {
    xmlSecBuffer buf;
    gcry_mpi_t res = NULL;
    gcry_error_t err;
    int ret;

    xmlSecAssert2(cur != NULL, NULL);

    ret = xmlSecBufferInitialize(&buf, 128);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecBufferInitialize",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(NULL);
    }

    ret = xmlSecBufferBase64NodeContentRead(&buf, cur);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecBufferBase64NodeContentRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        xmlSecBufferFinalize(&buf);
        return(NULL);
    }

    err = gcry_mpi_scan(&res, GCRYMPI_FMT_USG,
                         xmlSecBufferGetData(&buf),
                         xmlSecBufferGetSize(&buf),
                         NULL);
    if((err != GPG_ERR_NO_ERROR) || (res == NULL)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_mpi_scan",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    "err=%d", (int)err);
        xmlSecBufferFinalize(&buf);
        return(NULL);
    }

    /* done */
    xmlSecBufferFinalize(&buf);
    return(res);
}

/**
 * xmlSecGnuTLSNodeSetMpiValue:
 * @cur: the pointer to an XML node.
 * @a: the mpi value
 * @addLineBreaks: if the flag is equal to 1 then
 *              linebreaks will be added before and after
 *              new buffer content.
 *
 * Converts MPI to CryptoBinary string
 * (http://www.w3.org/TR/xmldsig-core/#sec-CryptoBinary)
 * and sets it as the content of the given node. If the
 * addLineBreaks is set then line breaks are added
 * before and after the CryptoBinary string.
 *
 * Returns: 0 on success or -1 otherwise.
 */
static int
xmlSecGnuTLSNodeSetMpiValue(xmlNodePtr cur, const gcry_mpi_t a, int addLineBreaks) {
    xmlSecBuffer buf;
    gcry_error_t err;
    size_t written = 0;
    int ret;

    xmlSecAssert2(a != NULL, -1);
    xmlSecAssert2(cur != NULL, -1);

    written = 0;
    err = gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &written, a);
    if((err != GPG_ERR_NO_ERROR) || (written == 0)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_mpi_print",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    "err=%d", (int)err);
        return(-1);
    }

    ret = xmlSecBufferInitialize(&buf, written + 1);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecBufferInitialize",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "size=%d", (int)written + 1);
        return(-1);
    }

    written = 0;
    err = gcry_mpi_print(GCRYMPI_FMT_USG,
            xmlSecBufferGetData(&buf),
            xmlSecBufferGetMaxSize(&buf),
            &written, a);
    if((err != GPG_ERR_NO_ERROR) || (written == 0)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_mpi_print",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    "err=%d,size=%d",
                    (int)err, (int)xmlSecBufferGetMaxSize(&buf));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    ret = xmlSecBufferSetSize(&buf, written);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecBufferSetSize",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "written=%d", (int)written);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    if(addLineBreaks) {
        xmlNodeSetContent(cur, xmlSecStringCR);
    } else {
        xmlNodeSetContent(cur, xmlSecStringEmpty);
    }

    ret = xmlSecBufferBase64NodeContentWrite(&buf, cur, xmlSecBase64GetDefaultLineSize());
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecBufferBase64NodeContentWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    if(addLineBreaks) {
        xmlNodeAddContent(cur, xmlSecStringCR);
    }

    xmlSecBufferFinalize(&buf);
    return(0);
}

/**
 * xmlSecGnuTLSNodeSetSExpTokValue:
 * @cur: the pointer to an XML node.
 * @sexp: the sexp
 * @tok: the token
 * @addLineBreaks: if the flag is equal to 1 then
 *              linebreaks will be added before and after
 *              new buffer content.
 *
 * Converts MPI to CryptoBinary string
 * (http://www.w3.org/TR/xmldsig-core/#sec-CryptoBinary)
 * and sets it as the content of the given node. If the
 * addLineBreaks is set then line breaks are added
 * before and after the CryptoBinary string.
 *
 * Returns: 0 on success or -1 otherwise.
 */
static int
xmlSecGnuTLSNodeSetSExpTokValue(xmlNodePtr cur, const gcry_sexp_t sexp,
                                const char * tok, int addLineBreaks)
{
    gcry_sexp_t val = NULL;
    gcry_mpi_t mpi = NULL;
    int res = -1;

    xmlSecAssert2(cur != NULL, -1);
    xmlSecAssert2(sexp != NULL, -1);
    xmlSecAssert2(tok != NULL, -1);

    val = gcry_sexp_find_token(sexp, tok, 0);
    if(val == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_sexp_find_token",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "tok=%s",
                    xmlSecErrorsSafeString(tok));
        goto done;
    }

    mpi = gcry_sexp_nth_mpi(val, 1, GCRYMPI_FMT_USG);
    if(mpi == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_sexp_nth_mpi",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "tok=%s",
                    xmlSecErrorsSafeString(tok));
        goto done;
    }

    /* almost done */
    res = xmlSecGnuTLSNodeSetMpiValue(cur, mpi, addLineBreaks);

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
static int              xmlSecGnuTLSKeyDataDsaInitialize        (xmlSecKeyDataPtr data);
static int              xmlSecGnuTLSKeyDataDsaDuplicate         (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
static void             xmlSecGnuTLSKeyDataDsaFinalize          (xmlSecKeyDataPtr data);
static int              xmlSecGnuTLSKeyDataDsaXmlRead           (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecGnuTLSKeyDataDsaXmlWrite          (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecGnuTLSKeyDataDsaGenerate          (xmlSecKeyDataPtr data,
                                                                 xmlSecSize sizeBits,
                                                                 xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecGnuTLSKeyDataDsaGetType          (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecGnuTLSKeyDataDsaGetSize           (xmlSecKeyDataPtr data);
static void             xmlSecGnuTLSKeyDataDsaDebugDump         (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecGnuTLSKeyDataDsaDebugXmlDump      (xmlSecKeyDataPtr data,
                                                                 FILE* output);

static xmlSecKeyDataKlass xmlSecGnuTLSKeyDataDsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecGnuTLSAsymKeyDataSize,

    /* data */
    xmlSecNameDSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefDSAKeyValue,                      /* const xmlChar* href; */
    xmlSecNodeDSAKeyValue,                      /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecGnuTLSKeyDataDsaInitialize,          /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecGnuTLSKeyDataDsaDuplicate,           /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecGnuTLSKeyDataDsaFinalize,            /* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecGnuTLSKeyDataDsaGenerate,            /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecGnuTLSKeyDataDsaGetType,             /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecGnuTLSKeyDataDsaGetSize,             /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecGnuTLSKeyDataDsaXmlRead,             /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecGnuTLSKeyDataDsaXmlWrite,            /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecGnuTLSKeyDataDsaDebugDump,           /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecGnuTLSKeyDataDsaDebugXmlDump,        /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSKeyDataDsaGetKlass:
 *
 * The DSA key data klass.
 *
 * Returns: pointer to DSA key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataDsaGetKlass(void) {
    return(&xmlSecGnuTLSKeyDataDsaKlass);
}

/**
 * xmlSecGnuTLSKeyDataDsaAdoptKey:
 * @data:               the pointer to DSA key data.
 * @dsa_key:            the pointer to GnuTLS DSA key.
 *
 * Sets the value of DSA key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataDsaAdoptKey(xmlSecKeyDataPtr data, gcry_sexp_t dsa_key) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId), -1);
    xmlSecAssert2(dsa_key != NULL, -1);

    return xmlSecGnuTLSAsymKeyDataAdoptKey(data, dsa_key);
}


/**
 * xmlSecGnuTLSKeyDataDsaAdoptKeyPair:
 * @data:               the pointer to DSA key data.
 * @pub_key:            the pointer to GnuTLS DSA pub key.
 * @priv_key:           the pointer to GnuTLS DSA priv key.
 *
 * Sets the value of DSA key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataDsaAdoptKeyPair(xmlSecKeyDataPtr data, gcry_sexp_t pub_key, gcry_sexp_t priv_key) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId), -1);
    xmlSecAssert2(pub_key != NULL, -1);

    return xmlSecGnuTLSAsymKeyDataAdoptKeyPair(data, pub_key, priv_key);
}

/**
 * xmlSecGnuTLSKeyDataDsaGetPublicKey:
 * @data:               the pointer to DSA key data.
 *
 * Gets the GnuTLS DSA public key from DSA key data.
 *
 * Returns: pointer to GnuTLS public DSA key or NULL if an error occurs.
 */
gcry_sexp_t
xmlSecGnuTLSKeyDataDsaGetPublicKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId), NULL);
    return xmlSecGnuTLSAsymKeyDataGetPublicKey(data);
}

/**
 * xmlSecGnuTLSKeyDataDsaGetPrivateKey:
 * @data:               the pointer to DSA key data.
 *
 * Gets the GnuTLS DSA private key from DSA key data.
 *
 * Returns: pointer to GnuTLS private DSA key or NULL if an error occurs.
 */
gcry_sexp_t
xmlSecGnuTLSKeyDataDsaGetPrivateKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId), NULL);
    return xmlSecGnuTLSAsymKeyDataGetPrivateKey(data);
}

static int
xmlSecGnuTLSKeyDataDsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId), -1);

    return(xmlSecGnuTLSAsymKeyDataInitialize(data));
}

static int
xmlSecGnuTLSKeyDataDsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecGnuTLSKeyDataDsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecGnuTLSKeyDataDsaId), -1);

    return(xmlSecGnuTLSAsymKeyDataDuplicate(dst, src));
}

static void
xmlSecGnuTLSKeyDataDsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId));

    xmlSecGnuTLSAsymKeyDataFinalize(data);
}


static int
xmlSecGnuTLSKeyDataDsaXmlRead(xmlSecKeyDataId id,
                              xmlSecKeyPtr key,
                              xmlNodePtr node,
                              xmlSecKeyInfoCtxPtr keyInfoCtx)
{
    xmlNodePtr cur;
    xmlSecKeyDataPtr data = NULL;
    gcry_mpi_t p = NULL;
    gcry_mpi_t q = NULL;
    gcry_mpi_t g = NULL;
    gcry_mpi_t x = NULL;
    gcry_mpi_t y = NULL;
    gcry_sexp_t pub_key = NULL;
    gcry_sexp_t priv_key = NULL;
    gcry_error_t err;
    int res = -1;
    int ret;

    xmlSecAssert2(id == xmlSecGnuTLSKeyDataDsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_KEY_DATA,
                    XMLSEC_ERRORS_NO_MESSAGE);
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
        goto done;
    }
    p = xmlSecGnuTLSNodeGetMpiValue(cur);
    if(p == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecGnuTLSNodeGetMpiValue",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "node=%s",
                    xmlSecErrorsSafeString(xmlSecNodeDSAP));
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
        goto done;
    }
    q = xmlSecGnuTLSNodeGetMpiValue(cur);
    if(q == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecGnuTLSNodeGetMpiValue",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "node=%s",
                    xmlSecErrorsSafeString(xmlSecNodeDSAQ));
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
        goto done;
    }
    g = xmlSecGnuTLSNodeGetMpiValue(cur);
    if(g == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecGnuTLSNodeGetMpiValue",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "node=%s",
                    xmlSecErrorsSafeString(xmlSecNodeDSAG));
        goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAX, xmlSecNs))) {
        /* next is X node. It is REQUIRED for private key but
         * we are not sure exactly what do we read */
        x = xmlSecGnuTLSNodeGetMpiValue(cur);
        if(x == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                        "xmlSecGnuTLSNodeGetMpiValue",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "node=%s",
                        xmlSecErrorsSafeString(xmlSecNodeDSAX));
            goto done;
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
        goto done;
    }
    y = xmlSecGnuTLSNodeGetMpiValue(cur);
    if(y == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecGnuTLSNodeGetMpiValue",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
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
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
                    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }


    /* construct pub/priv key pairs */
    err = gcry_sexp_build(&pub_key, NULL,
             "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
             p, q, g, y);
    if((err != GPG_ERR_NO_ERROR) || (pub_key == NULL)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
                    "gcry_sexp_build(public)",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }
    if(x != NULL) {
        err = gcry_sexp_build(&priv_key, NULL,
                 "(private-key(dsa(p%m)(q%m)(g%m)(x%m)(y%m)))",
                 p, q, g, x, y);
        if((err != GPG_ERR_NO_ERROR) || (priv_key == NULL)) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
                        "gcry_sexp_build(private)",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            goto done;
        }
    }

    /* create key data */
    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecKeyDataCreate",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }

    ret = xmlSecGnuTLSKeyDataDsaAdoptKeyPair(data, pub_key, priv_key);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
                    "xmlSecGnuTLSKeyDataDsaAdoptKeyPair",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }
    pub_key = NULL; /* pub_key is owned by data now */
    priv_key = NULL; /* priv_key is owned by data now */

    /* set key */
    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
                    "xmlSecKeySetValue",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }
    data = NULL; /* data is owned by key now */

    /* success */
    res = 0;

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
xmlSecGnuTLSKeyDataDsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlNodePtr cur;
    gcry_sexp_t pub_priv_key;
    gcry_sexp_t dsa = NULL;
    int private = 0;
    int res = -1;
    int ret;

    xmlSecAssert2(id == xmlSecGnuTLSKeyDataDsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecGnuTLSKeyDataDsaId), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(((xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate) & keyInfoCtx->keyReq.keyType) == 0) {
        /* we can have only private key or public key */
        return(0);
    }

    /* find the private or public key */
    pub_priv_key = xmlSecGnuTLSKeyDataDsaGetPrivateKey(xmlSecKeyGetValue(key));
    if(pub_priv_key == NULL) {
        pub_priv_key = xmlSecGnuTLSKeyDataDsaGetPublicKey(xmlSecKeyGetValue(key));
        if(pub_priv_key == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                        "xmlSecGnuTLSKeyDataDsaGetPublicKey()",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            goto done;
        }
    } else {
        private = 1;
    }

    dsa = gcry_sexp_find_token(pub_priv_key, "dsa", 0);
    if(dsa == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "gcry_sexp_find_token(dsa)",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }

    /* first is P node */
    cur = xmlSecAddChild(node, xmlSecNodeDSAP, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecAddChild",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "node=%s",
                    xmlSecErrorsSafeString(xmlSecNodeDSAP));
        goto done;
    }
    ret = xmlSecGnuTLSNodeSetSExpTokValue(cur, dsa, "p", 1);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecGnuTLSNodeSetSExpTokValue",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "node=%s",
                    xmlSecErrorsSafeString(xmlSecNodeDSAP));
        goto done;
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
        goto done;
    }
    ret = xmlSecGnuTLSNodeSetSExpTokValue(cur, dsa, "q", 1);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecGnuTLSNodeSetSExpTokValue",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "node=%s",
                    xmlSecErrorsSafeString(xmlSecNodeDSAQ));
        goto done;
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
        goto done;
    }
    ret = xmlSecGnuTLSNodeSetSExpTokValue(cur, dsa, "g", 1);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecGnuTLSNodeSetSExpTokValue",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "node=%s",
                    xmlSecErrorsSafeString(xmlSecNodeDSAG));
        goto done;
    }

    /* next is X node: write it ONLY for private keys and ONLY if it is requested */
    if(((keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypePrivate) != 0) && (private != 0)) {
        cur = xmlSecAddChild(node, xmlSecNodeDSAX, xmlSecNs);
        if(cur == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                        "xmlSecAddChild",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "node=%s",
                        xmlSecErrorsSafeString(xmlSecNodeDSAX));
            goto done;
        }
        ret = xmlSecGnuTLSNodeSetSExpTokValue(cur, dsa, "x", 1);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                        "xmlSecGnuTLSNodeSetSExpTokValue",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "node=%s",
                        xmlSecErrorsSafeString(xmlSecNodeDSAX));
            goto done;
        }
    }

    /* next is Y node. */
    cur = xmlSecAddChild(node, xmlSecNodeDSAY, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecAddChild",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "node=%s",
                    xmlSecErrorsSafeString(xmlSecNodeDSAY));
        goto done;
    }
    ret = xmlSecGnuTLSNodeSetSExpTokValue(cur, dsa, "y", 1);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecGnuTLSNodeSetSExpTokValue",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "node=%s",
                    xmlSecErrorsSafeString(xmlSecNodeDSAY));
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

static int
xmlSecGnuTLSKeyDataDsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    return xmlSecGnuTLSAsymKeyDataGenerate(data, "dsa", sizeBits);
}

static xmlSecKeyDataType
xmlSecGnuTLSKeyDataDsaGetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId), xmlSecKeyDataTypeUnknown);

    return xmlSecGnuTLSAsymKeyDataGetType(data);
}

static xmlSecSize
xmlSecGnuTLSKeyDataDsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId), 0);

    return xmlSecGnuTLSAsymKeyDataGetSize(data);
}

static void
xmlSecGnuTLSKeyDataDsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== dsa key: size = %d\n",
            xmlSecGnuTLSKeyDataDsaGetSize(data));
}

static void
xmlSecGnuTLSKeyDataDsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<DSAKeyValue size=\"%d\" />\n",
            xmlSecGnuTLSKeyDataDsaGetSize(data));
}

#endif /* XMLSEC_NO_DSA */


#ifdef ALEKSEY_TODO
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

static int              xmlSecGnuTLSKeyDataRsaInitialize       (xmlSecKeyDataPtr data);
static int              xmlSecGnuTLSKeyDataRsaDuplicate        (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
static void             xmlSecGnuTLSKeyDataRsaFinalize         (xmlSecKeyDataPtr data);
static int              xmlSecGnuTLSKeyDataRsaXmlRead          (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecGnuTLSKeyDataRsaXmlWrite         (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecGnuTLSKeyDataRsaGenerate         (xmlSecKeyDataPtr data,
                                                                 xmlSecSize sizeBits,
                                                                 xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecGnuTLSKeyDataRsaGetType         (xmlSecKeyDataPtr data);
static xmlSecSize               xmlSecGnuTLSKeyDataRsaGetSize          (xmlSecKeyDataPtr data);
static void             xmlSecGnuTLSKeyDataRsaDebugDump        (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecGnuTLSKeyDataRsaDebugXmlDump     (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static xmlSecKeyDataKlass xmlSecGnuTLSKeyDataRsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecGnuTLSAsymKeyDataSize,

    /* data */
    xmlSecNameRSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefRSAKeyValue,                      /* const xmlChar* href; */
    xmlSecNodeRSAKeyValue,                      /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecGnuTLSKeyDataRsaInitialize,          /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecGnuTLSKeyDataRsaDuplicate,           /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecGnuTLSKeyDataRsaFinalize,            /* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecGnuTLSKeyDataRsaGenerate,            /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecGnuTLSKeyDataRsaGetType,             /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecGnuTLSKeyDataRsaGetSize,             /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecGnuTLSKeyDataRsaXmlRead,             /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecGnuTLSKeyDataRsaXmlWrite,            /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecGnuTLSKeyDataRsaDebugDump,           /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecGnuTLSKeyDataRsaDebugXmlDump,        /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSKeyDataRsaGetKlass:
 *
 * The GnuTLS RSA key data klass.
 *
 * Returns: pointer to GnuTLS RSA key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataRsaGetKlass(void) {
    return(&xmlSecGnuTLSKeyDataRsaKlass);
}

/**
 * xmlSecGnuTLSKeyDataRsaAdoptRsa:
 * @data:               the pointer to RSA key data.
 * @rsa:                the pointer to GnuTLS RSA key.
 *
 * Sets the value of RSA key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataRsaAdoptRsa(xmlSecKeyDataPtr data, RSA* rsa) {
    EVP_PKEY* pKey = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), -1);

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

    ret = xmlSecGnuTLSKeyDataRsaAdoptEvp(data, pKey);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
                    "xmlSecGnuTLSKeyDataRsaAdoptEvp",
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
 * xmlSecGnuTLSKeyDataRsaGetRsa:
 * @data:               the pointer to RSA key data.
 *
 * Gets the GnuTLS RSA key from RSA key data.
 *
 * Returns: pointer to GnuTLS RSA key or NULL if an error occurs.
 */
RSA*
xmlSecGnuTLSKeyDataRsaGetRsa(xmlSecKeyDataPtr data) {
    EVP_PKEY* pKey;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), NULL);

    pKey = xmlSecGnuTLSKeyDataRsaGetEvp(data);
    xmlSecAssert2((pKey == NULL) || (pKey->type == EVP_PKEY_RSA), NULL);

    return((pKey != NULL) ? pKey->pkey.rsa : (RSA*)NULL);
}

/**
 * xmlSecGnuTLSKeyDataRsaAdoptEvp:
 * @data:               the pointer to RSA key data.
 * @pKey:               the pointer to GnuTLS EVP key.
 *
 * Sets the RSA key data value to GnuTLS EVP key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataRsaAdoptEvp(xmlSecKeyDataPtr data, EVP_PKEY* pKey) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), -1);
    xmlSecAssert2(pKey != NULL, -1);
    xmlSecAssert2(pKey->type == EVP_PKEY_RSA, -1);

    return(xmlSecGnuTLSAsymKeyDataAdoptEvp(data, pKey));
}

/**
 * xmlSecGnuTLSKeyDataRsaGetEvp:
 * @data:               the pointer to RSA key data.
 *
 * Gets the GnuTLS EVP key from RSA key data.
 *
 * Returns: pointer to GnuTLS EVP key or NULL if an error occurs.
 */
EVP_PKEY*
xmlSecGnuTLSKeyDataRsaGetEvp(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), NULL);

    return(xmlSecGnuTLSAsymKeyDataGetEvp(data));
}

static int
xmlSecGnuTLSKeyDataRsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), -1);

    return(xmlSecGnuTLSAsymKeyDataInitialize(data));
}

static int
xmlSecGnuTLSKeyDataRsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecGnuTLSKeyDataRsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecGnuTLSKeyDataRsaId), -1);

    return(xmlSecGnuTLSAsymKeyDataDuplicate(dst, src));
}

static void
xmlSecGnuTLSKeyDataRsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId));

    xmlSecGnuTLSAsymKeyDataFinalize(data);
}

static int
xmlSecGnuTLSKeyDataRsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    xmlNodePtr cur;
    RSA *rsa;
    int ret;

    xmlSecAssert2(id == xmlSecGnuTLSKeyDataRsaId, -1);
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
    if(xmlSecGnuTLSNodeGetMpiValue(cur, &(rsa->n)) == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecGnuTLSNodeGetMpiValue",
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
    if(xmlSecGnuTLSNodeGetMpiValue(cur, &(rsa->e)) == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecGnuTLSNodeGetMpiValue",
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
        if(xmlSecGnuTLSNodeGetMpiValue(cur, &(rsa->d)) == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                        "xmlSecGnuTLSNodeGetMpiValue",
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

    ret = xmlSecGnuTLSKeyDataRsaAdoptRsa(data, rsa);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecGnuTLSKeyDataRsaAdoptRsa",
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
xmlSecGnuTLSKeyDataRsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                            xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlNodePtr cur;
    RSA* rsa;
    int ret;

    xmlSecAssert2(id == xmlSecGnuTLSKeyDataRsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecGnuTLSKeyDataRsaId), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    rsa = xmlSecGnuTLSKeyDataRsaGetRsa(xmlSecKeyGetValue(key));
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
    ret = xmlSecGnuTLSNodeSetSExpTokValue(cur, rsa->n, 1);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecGnuTLSNodeSetSExpTokValue",
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
    ret = xmlSecGnuTLSNodeSetSExpTokValue(cur, rsa->e, 1);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                    "xmlSecGnuTLSNodeSetSExpTokValue",
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
        ret = xmlSecGnuTLSNodeSetSExpTokValue(cur, rsa->d, 1);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
                        "xmlSecGnuTLSNodeSetSExpTokValue",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "node=%s",
                        xmlSecErrorsSafeString(xmlSecNodeRSAPrivateExponent));
            return(-1);
        }
    }

    return(0);
}

static int
xmlSecGnuTLSKeyDataRsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    RSA* rsa;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), -1);
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

    ret = xmlSecGnuTLSKeyDataRsaAdoptRsa(data, rsa);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
                    "xmlSecGnuTLSKeyDataRsaAdoptRsa",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        RSA_free(rsa);
        return(-1);
    }

    return(0);
}

static xmlSecKeyDataType
xmlSecGnuTLSKeyDataRsaGetType(xmlSecKeyDataPtr data) {
    RSA* rsa;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), xmlSecKeyDataTypeUnknown);

    rsa = xmlSecGnuTLSKeyDataRsaGetRsa(data);
    if((rsa != NULL) && (rsa->n != NULL) && (rsa->e != NULL)) {
        if(rsa->d != NULL) {
            return(xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
        } else if(rsa->engine != NULL) {
            /*
             * !!! HACK !!! Also see DSA key
             * We assume here that engine *always* has private key.
             * This might be incorrect but it seems that there is no
             * way to ask engine if given key is private or not.
             */
            return(xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
        } else {
            return(xmlSecKeyDataTypePublic);
        }
    }

    return(xmlSecKeyDataTypeUnknown);
}

static xmlSecSize
xmlSecGnuTLSKeyDataRsaGetSize(xmlSecKeyDataPtr data) {
    RSA* rsa;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), 0);

    rsa = xmlSecGnuTLSKeyDataRsaGetRsa(data);
    if((rsa != NULL) && (rsa->n != NULL)) {
        return(BN_num_bits(rsa->n));
    }
    return(0);
}

static void
xmlSecGnuTLSKeyDataRsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== rsa key: size = %d\n",
            xmlSecGnuTLSKeyDataRsaGetSize(data));
}

static void
xmlSecGnuTLSKeyDataRsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<RSAKeyValue size=\"%d\" />\n",
            xmlSecGnuTLSKeyDataRsaGetSize(data));
}

#endif /* XMLSEC_NO_RSA */
#endif /* ALEKSEY_TODO */


