/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:asymkeys
 * @Short_description: Asymmetric keys implementation for GnuTLS.
 * @Stability: Private
 *
 */

#include "globals.h"

#include <string.h>

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/base64.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gnutls/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"

/**************************************************************************
 *
 * Internal GnuTLS asym key CTX
 *
 *************************************************************************/
typedef struct _xmlSecGnuTLSAsymKeyDataCtx       xmlSecGnuTLSAsymKeyDataCtx,
                                                *xmlSecGnuTLSAsymKeyDataCtxPtr;
struct _xmlSecGnuTLSAsymKeyDataCtx {
    gnutls_pubkey_t   pubkey;
    gnutls_privkey_t  privkey;
};

/******************************************************************************
 *
 * GnuTLS asym key data (dsa/rsa/ecdsa)
 *
 *****************************************************************************/
XMLSEC_KEY_DATA_DECLARE(GnuTLSAsymKeyData, xmlSecGnuTLSAsymKeyDataCtx)
#define xmlSecGnuTLSAsymKeyDataSize XMLSEC_KEY_DATA_SIZE(GnuTLSAsymKeyData)

static int              xmlSecGnuTLSAsymKeyDataInitialize       (xmlSecKeyDataPtr data);
static void             xmlSecGnuTLSAsymKeyDataFinalize         (xmlSecKeyDataPtr data);

static int              xmlSecGnuTLSAsymKeyDataAdoptKey         (xmlSecKeyDataPtr data,
                                                                 gnutls_pubkey_t pubkey,
                                                                 gnutls_privkey_t privkey);
static int              xmlSecGnuTLSAsymKeyDataGenerate         (xmlSecKeyDataPtr data,
                                                                 gnutls_pk_algorithm_t algo,
                                                                 xmlSecSize key_size);
static int              xmlSecGnuTLSAsymKeyDataDuplicate        (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);

static gnutls_pubkey_t  xmlSecGnuTLSAsymKeyDataGetPublicKey     (xmlSecKeyDataPtr data);
static gnutls_privkey_t xmlSecGnuTLSAsymKeyDataGetPrivateKey    (xmlSecKeyDataPtr data);
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

static void
xmlSecGnuTLSAsymKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize));

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    if(ctx->pubkey != NULL) {
        gnutls_pubkey_deinit(ctx->pubkey);
    }
    if(ctx->privkey != NULL) {
        gnutls_privkey_deinit (ctx->privkey);
    }
    memset(ctx, 0, sizeof(xmlSecGnuTLSAsymKeyDataCtx));
}

static int
xmlSecGnuTLSAsymKeyDataAdoptKey(xmlSecKeyDataPtr data, gnutls_pubkey_t pubkey, gnutls_privkey_t privkey) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), -1);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    /* deinit if anything */
    if(ctx->pubkey != NULL) {
        gnutls_pubkey_deinit(ctx->pubkey);
    }
    if(ctx->privkey != NULL) {
        gnutls_privkey_deinit (ctx->privkey);
    }

    ctx->pubkey = pubkey;
    ctx->privkey = privkey;

    /* done */
    return(0);
}

static int
xmlSecGnuTLSAsymKeyDataGenerate(xmlSecKeyDataPtr data, gnutls_pk_algorithm_t algo, xmlSecSize key_size) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;
    gnutls_privkey_t privkey;
    unsigned int bits;
    int err;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), -1);
    xmlSecAssert2(algo != GNUTLS_PK_UNKNOWN, -1);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_UINT(key_size, bits, return(-1), NULL);

    err = gnutls_privkey_init(&privkey);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_privkey_init", err, NULL);
        return(-1);
    }

    err = gnutls_privkey_generate(privkey, algo, bits, 0);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_privkey_generate", err, NULL);
        gnutls_privkey_deinit(privkey);
        return(-1);
    }

    ret = xmlSecGnuTLSAsymKeyDataAdoptKey(data, NULL, privkey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSAsymKeyDataAdoptKey", NULL);
        gnutls_privkey_deinit(privkey);
        return(-1);
    }
    privkey = NULL; /* owned by data */

    /* success */
    return(0);
}

static int
xmlSecGnuTLSAsymKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctxDst;
    xmlSecGnuTLSAsymKeyDataCtxPtr ctxSrc;
    int err;

    xmlSecAssert2(xmlSecKeyDataIsValid(dst), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(dst, xmlSecGnuTLSAsymKeyDataSize), -1);
    xmlSecAssert2(xmlSecKeyDataIsValid(src), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(src, xmlSecGnuTLSAsymKeyDataSize), -1);

    ctxDst = xmlSecGnuTLSAsymKeyDataGetCtx(dst);
    xmlSecAssert2(ctxDst != NULL, -1);
    xmlSecAssert2(ctxDst->pubkey == NULL, -1);
    xmlSecAssert2(ctxDst->privkey == NULL, -1);

    ctxSrc = xmlSecGnuTLSAsymKeyDataGetCtx(src);
    xmlSecAssert2(ctxSrc != NULL, -1);

    /* public key */
    if(ctxSrc->pubkey != NULL) {
        gnutls_datum_t pubkey = { NULL, 0 };

        err = gnutls_pubkey_export2(ctxSrc->pubkey, GNUTLS_X509_FMT_DER, &pubkey);
        if((err != GNUTLS_E_SUCCESS) || (pubkey.data == NULL)) {
            xmlSecGnuTLSError("gnutls_pubkey_export2", err, NULL);
            return(-1);
        }

        err = gnutls_pubkey_init(&ctxDst->pubkey);
        if (err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_pubkey_init", err, NULL);
            gnutls_free(pubkey.data);
            return(-1);
        }

        err = gnutls_pubkey_import(ctxDst->pubkey, &pubkey, GNUTLS_X509_FMT_DER);
        if (err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_pubkey_import", err, NULL);
            gnutls_free(pubkey.data);
            return(-1);
        }
        gnutls_free(pubkey.data);
    }

    /* private key */
    if(ctxSrc->privkey != NULL) {
        gnutls_x509_privkey_t x509_privkey = NULL;

        err = gnutls_privkey_export_x509(ctxSrc->privkey, &x509_privkey);
        if (err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_privkey_export_x509", err, NULL);
            return(-1);
        }

        err = gnutls_privkey_init(&ctxDst->privkey);
        if (err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_privkey_init", err, NULL);
            gnutls_x509_privkey_deinit(x509_privkey);
            return(-1);
        }

        err = gnutls_privkey_import_x509(ctxDst->privkey, x509_privkey, GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);
        if (err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_privkey_import_x509", err, NULL);
            gnutls_x509_privkey_deinit(x509_privkey);
            return(-1);
        }
        x509_privkey = NULL; /* owned by privkey now */
    }

    /* done */
    return(0);
}

static gnutls_pubkey_t
xmlSecGnuTLSAsymKeyDataGetPublicKey(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), NULL);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->pubkey);
}

static gnutls_privkey_t
xmlSecGnuTLSAsymKeyDataGetPrivateKey(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), NULL);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->privkey);
}

static xmlSecKeyDataType
xmlSecGnuTLSAsymKeyDataGetType(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, xmlSecKeyDataTypeUnknown);

    if((ctx->privkey != NULL) && (ctx->pubkey != NULL)) {
        return (xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
    } else if(ctx->privkey != NULL) {
        return (xmlSecKeyDataTypePrivate);
    } else if(ctx->pubkey != NULL) {
        return (xmlSecKeyDataTypePublic);
    }

    return (xmlSecKeyDataTypeUnknown);
}

static xmlSecSize
xmlSecGnuTLSAsymKeyDataGetSize(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;
    unsigned int bits = 0;
    xmlSecSize res;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    if(ctx->pubkey != NULL) {
        ret = gnutls_pubkey_get_pk_algorithm(ctx->pubkey, &bits);
        if(ret < 0) {
            xmlSecGnuTLSError("gnutls_pubkey_get_pk_algorithm", ret, NULL);
            return(0);
        }
        XMLSEC_SAFE_CAST_UINT_TO_SIZE(bits, res, return(-1), NULL);
        return(res);
    }

    if(ctx->privkey != NULL) {
        ret = gnutls_privkey_get_pk_algorithm(ctx->privkey, &bits);
        if(ret < 0) {
            xmlSecGnuTLSError("gnutls_privkey_get_pk_algorithm", ret, NULL);
            return(0);
        }
        XMLSEC_SAFE_CAST_UINT_TO_SIZE(bits, res, return(-1), NULL);
        return(res);
    }

    xmlSecInternalError("Neither public nor private keys are set", NULL);
    return(0);
}


#ifndef XMLSEC_NO_DSA
/**************************************************************************
 *
 * <dsig:DSAKeyValue> processing
 *
 *
 * The DSAKeyValue Element (http://www.w3.org/TR/xmldsig-core/#sec-DSAKeyValue)
 *
 **************************************************************************/

static int              xmlSecGnuTLSKeyDataDsaInitialize        (xmlSecKeyDataPtr data);
static void             xmlSecGnuTLSKeyDataDsaFinalize          (xmlSecKeyDataPtr data);
static int              xmlSecGnuTLSKeyDataDsaGenerate          (xmlSecKeyDataPtr data,
                                                                 xmlSecSize sizeBits,
                                                                 xmlSecKeyDataType type);
static int              xmlSecGnuTLSKeyDataDsaDuplicate         (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);


static xmlSecKeyDataType xmlSecGnuTLSKeyDataDsaGetType          (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecGnuTLSKeyDataDsaGetSize           (xmlSecKeyDataPtr data);
static void             xmlSecGnuTLSKeyDataDsaDebugDump         (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecGnuTLSKeyDataDsaDebugXmlDump      (xmlSecKeyDataPtr data,
                                                                 FILE* output);

static int              xmlSecGnuTLSKeyDataDsaXmlRead           (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecGnuTLSKeyDataDsaXmlWrite          (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyDataPtr xmlSecGnuTLSKeyDataDsaRead              (xmlSecKeyDataId id,
                                                                 xmlSecKeyValueDsaPtr dsaValue);
static int              xmlSecGnuTLSKeyDataDsaWrite             (xmlSecKeyDataId id,
                                                                 xmlSecKeyDataPtr data,
                                                                 xmlSecKeyValueDsaPtr dsaValue,
                                                                 int writePrivateKey);

static gnutls_pubkey_t  xmlSecGnuTLSKeyDataPubKeyFromPrivKey    (gnutls_privkey_t privkey);

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
    xmlSecGnuTLSKeyDataDsaGenerate,            /* xmlSecKeyDatavMethod generate; */

    /* get info */
    xmlSecGnuTLSKeyDataDsaGetType,              /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecGnuTLSKeyDataDsaGetSize,              /* xmlSecKeyDataGetSizeMethod getSize; */
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
 * @pubkey:             the pointer to GnuTLS DSA key.
 * @privkey:            the pointer to GnuTLS DSA key.
 *
 * Sets the value of DSA key data. The @pubkey and @privkey will be owned by the @data on success.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataDsaAdoptKey(xmlSecKeyDataPtr data, gnutls_pubkey_t pubkey, gnutls_privkey_t privkey) {
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId), -1);

    /* verify key type */
    if(pubkey != NULL) {
        ret = gnutls_pubkey_get_pk_algorithm(pubkey, NULL);
        if(ret != GNUTLS_PK_DSA) {
            xmlSecInternalError2("Invalid pubkey algorithm", NULL, "type=%d", ret);
            return(-1);
        }
    }
    if(privkey != NULL) {
        ret = gnutls_privkey_get_pk_algorithm(privkey, NULL);
        if(ret != GNUTLS_PK_DSA) {
            xmlSecInternalError2("Invalid privkey algorithm", NULL, "type=%d", ret);
            return(-1);
        }
    }

    /* create pub key if needed */
    if((privkey != NULL) && (pubkey == NULL)) {
        pubkey = xmlSecGnuTLSKeyDataPubKeyFromPrivKey(privkey);
        if(pubkey == NULL) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataPubKeyFromPrivKey", NULL);
            return(-1);
        }
    }

    /* do the work */
    return xmlSecGnuTLSAsymKeyDataAdoptKey(data, pubkey, privkey);
}

/**
 * xmlSecGnuTLSKeyDataDsaGetPublicKey:
 * @data:               the pointer to DSA key data.
 *
 * Gets the GnuTLS DSA public key from DSA key data.
 *
 * Returns: pointer to GnuTLS public DSA key or NULL if an error occurs.
 */
gnutls_pubkey_t
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
gnutls_privkey_t
xmlSecGnuTLSKeyDataDsaGetPrivateKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId), NULL);
    return xmlSecGnuTLSAsymKeyDataGetPrivateKey(data);
}

static int
xmlSecGnuTLSKeyDataDsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId), -1);

    return(xmlSecGnuTLSAsymKeyDataInitialize(data));
}

static void
xmlSecGnuTLSKeyDataDsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId));

    xmlSecGnuTLSAsymKeyDataFinalize(data);
}

static int
xmlSecGnuTLSKeyDataDsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecGnuTLSKeyDataDsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecGnuTLSKeyDataDsaId), -1);

    return(xmlSecGnuTLSAsymKeyDataDuplicate(dst, src));
}

static int
xmlSecGnuTLSKeyDataDsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    return xmlSecGnuTLSAsymKeyDataGenerate(data, GNUTLS_PK_DSA, sizeBits);
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

    fprintf(output, "=== dsa key: size = " XMLSEC_SIZE_FMT "\n",
            xmlSecGnuTLSKeyDataDsaGetSize(data));
}

static void
xmlSecGnuTLSKeyDataDsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<DSAKeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
            xmlSecGnuTLSKeyDataDsaGetSize(data));
}

static int
xmlSecGnuTLSKeyDataDsaXmlRead(xmlSecKeyDataId id,
                              xmlSecKeyPtr key,
                              xmlNodePtr node,
                              xmlSecKeyInfoCtxPtr keyInfoCtx)
{
    xmlSecAssert2(id == xmlSecGnuTLSKeyDataDsaId, -1);
    return(xmlSecKeyDataDsaXmlRead(id, key, node, keyInfoCtx,
        xmlSecGnuTLSKeyDataDsaRead));
}

static int
xmlSecGnuTLSKeyDataDsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecGnuTLSKeyDataDsaId, -1);
    return(xmlSecKeyDataDsaXmlWrite(id, key, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecGnuTLSKeyDataDsaWrite));
}

static xmlSecKeyDataPtr
xmlSecGnuTLSKeyDataDsaRead(xmlSecKeyDataId id, xmlSecKeyValueDsaPtr dsaValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    xmlSecSize size;
	gnutls_datum_t p, q, g, y;
    gnutls_privkey_t privkey = NULL;
    gnutls_pubkey_t pubkey = NULL;
    int err;
    int ret;

    xmlSecAssert2(id == xmlSecGnuTLSKeyDataDsaId, NULL);
    xmlSecAssert2(dsaValue != NULL, NULL);

    /*** p ***/
    size = xmlSecBufferGetSize(&(dsaValue->p));
    p.data = xmlSecBufferGetData(&(dsaValue->p));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, p.size,  goto done, xmlSecKeyDataKlassGetName(id));

    /*** q ***/
    size = xmlSecBufferGetSize(&(dsaValue->q));
    q.data = xmlSecBufferGetData(&(dsaValue->q));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, q.size,  goto done, xmlSecKeyDataKlassGetName(id));

    /*** g ***/
    size = xmlSecBufferGetSize(&(dsaValue->g));
    g.data = xmlSecBufferGetData(&(dsaValue->g));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, g.size,  goto done, xmlSecKeyDataKlassGetName(id));

    /*** y ***/
    size = xmlSecBufferGetSize(&(dsaValue->y));
    y.data = xmlSecBufferGetData(&(dsaValue->y));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, y.size,  goto done, xmlSecKeyDataKlassGetName(id));

    /*** x (only for private key) ***/
    size = xmlSecBufferGetSize(&(dsaValue->x));
    if(size > 0) {
        gnutls_datum_t x;

        x.data = xmlSecBufferGetData(&(dsaValue->x));
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, x.size, goto done, xmlSecKeyDataKlassGetName(id));

        err = gnutls_privkey_init(&privkey);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_privkey_init", err, xmlSecKeyDataKlassGetName(id));
            goto done;
        }

        err = gnutls_privkey_import_dsa_raw(privkey, &p, &q, &g, &y, &x);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_privkey_import_dsa_raw", err, xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    }

    /* pub key */
    err = gnutls_pubkey_init(&pubkey);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_init", err, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    err = gnutls_pubkey_import_dsa_raw(pubkey, &p, &q, &g, &y);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_import_dsa_raw", err, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* create key data */
    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
        xmlSecInternalError("xmlSecKeyDataCreate", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecGnuTLSKeyDataDsaAdoptKey(data, pubkey, privkey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSKeyDataDsaAdoptKey", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    pubkey = NULL; /* pubkey is owned by data now */
    privkey = NULL; /* privkey is owned by data now */

    /* success */
    res = data;
    data = NULL;

done:
    /* cleanup */
    if(privkey != NULL) {
        gnutls_privkey_deinit(privkey);
    }

    if(pubkey != NULL) {
        gnutls_pubkey_deinit(pubkey);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

static int
xmlSecGnuTLSKeyDataDsaWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data,
    xmlSecKeyValueDsaPtr dsaValue, int writePrivateKey)
{
    gnutls_privkey_t privkey = NULL;
    gnutls_pubkey_t pubkey = NULL;
	gnutls_datum_t p = { NULL, 0 };
    gnutls_datum_t q = { NULL, 0 };
    gnutls_datum_t g = { NULL, 0 };
    gnutls_datum_t y = { NULL, 0 };
    gnutls_datum_t x = { NULL, 0 };
    int ret;
    int err;
    int res = -1;

    xmlSecAssert2(id == xmlSecGnuTLSKeyDataDsaId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId), -1);
    xmlSecAssert2(dsaValue != NULL, -1);

    /* get components */
    privkey = xmlSecGnuTLSKeyDataDsaGetPrivateKey(data);
    pubkey = xmlSecGnuTLSKeyDataDsaGetPublicKey(data);
    if(privkey != NULL) {
        err = gnutls_privkey_export_dsa_raw2(privkey,
			       &p, &q, &g, &y, &x,
                   GNUTLS_EXPORT_FLAG_NO_LZ);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_privkey_export_dsa_raw2", err, xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    } else if(pubkey != NULL) {
        err = gnutls_pubkey_export_dsa_raw2(pubkey,
			       &p, &q, &g, &y,
                   GNUTLS_EXPORT_FLAG_NO_LZ);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_pubkey_export_dsa_raw2", err, xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    } else {
        xmlSecInternalError("Neither private or public keys are available", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* p */
    if((p.data == NULL) || (p.size <= 0)) {
        xmlSecInternalError("DSA p parameter is NULL", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = xmlSecBufferAppend(&(dsaValue->p), p.data, p.size);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(p)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* q */
    if((q.data == NULL) || (q.size <= 0)) {
        xmlSecInternalError("DSA q parameter is NULL", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = xmlSecBufferAppend(&(dsaValue->q), q.data, q.size);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(q)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* g */
    if((g.data == NULL) || (g.size <= 0)) {
        xmlSecInternalError("DSA g parameter is NULL", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = xmlSecBufferAppend(&(dsaValue->g), g.data, g.size);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(g)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* y */
    if((g.data == NULL) || (y.size <= 0)) {
        xmlSecInternalError("DSA y parameter is NULL", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = xmlSecBufferAppend(&(dsaValue->y), y.data, y.size);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(y)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /*** x (only if available and requested) ***/
    if((writePrivateKey != 0) && (privkey != NULL)) {
        if((x.data == NULL) || (x.size <= 0)) {
            xmlSecInternalError("DSA x parameter is NULL", xmlSecKeyDataKlassGetName(id));
            goto done;
        }
        ret = xmlSecBufferAppend(&(dsaValue->x), x.data, x.size);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferAppend(x)", xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    }

    /* success */
    res = 0;

done:
    if(p.data != NULL) {
        gnutls_free(p.data);
    }
    if(q.data != NULL) {
        gnutls_free(q.data);
    }
    if(g.data != NULL) {
        gnutls_free(g.data);
    }
    if(y.data != NULL) {
        gnutls_free(y.data);
    }
    if(x.data != NULL) {
        gnutls_free(x.data);
    }

    return(res);
}

static gnutls_pubkey_t
xmlSecGnuTLSKeyDataPubKeyFromPrivKey(gnutls_privkey_t privkey) {
    gnutls_pubkey_t pubkey = NULL;
	gnutls_datum_t p = { NULL, 0 };
    gnutls_datum_t q = { NULL, 0 };
    gnutls_datum_t g = { NULL, 0 };
    gnutls_datum_t y = { NULL, 0 };
    gnutls_datum_t x = { NULL, 0 };
    int err;

    xmlSecAssert2(privkey != NULL, NULL);

    err = gnutls_privkey_export_dsa_raw2(privkey,
                &p, &q, &g, &y, &x,
                0);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_privkey_export_dsa_raw2", err, NULL);
        goto done;
    }

    err = gnutls_pubkey_init(&pubkey);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_init", err, NULL);
        goto done;
    }

    err = gnutls_pubkey_import_dsa_raw(pubkey, &p, &q, &g, &y);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_import_dsa_raw", err, NULL);
        gnutls_pubkey_deinit(pubkey);
        goto done;
    }

done:
    if(p.data != NULL) {
        gnutls_free(p.data);
    }
    if(q.data != NULL) {
        gnutls_free(q.data);
    }
    if(g.data != NULL) {
        gnutls_free(g.data);
    }
    if(y.data != NULL) {
        gnutls_free(y.data);
    }
    if(x.data != NULL) {
        gnutls_free(x.data);
    }

    return(pubkey);
}

#endif /* XMLSEC_NO_DSA */

/**** OLD_CODE */


/**************************************************************************
 *
 * We use xmlsec-gcrypt for all the basic crypto ops
 *
 *****************************************************************************/
#include <xmlsec/gcrypt/crypto.h>
#include <gcrypt.h>

static void xmlSecGnuTLSDestroyParams(gnutls_datum_t * params, xmlSecSize num) {
    xmlSecSize ii;

    xmlSecAssert(params != NULL);
    for(ii = 0; ii < num; ++ii) {
        gnutls_free(params[ii].data);
    }
}

static void xmlSecGnuTLSDestroyMpis(gcry_mpi_t * mpis, xmlSecSize num) {
    xmlSecSize ii;

    xmlSecAssert(mpis != NULL);
    for(ii = 0; ii < num; ++ii) {
        gcry_mpi_release(mpis[ii]);
    }
}

static int xmlSecGnuTLSConvertParamsToMpis(gnutls_datum_t * params, xmlSecSize paramsNum,
                                           gcry_mpi_t * mpis, xmlSecSize mpisNum) {

    xmlSecSize ii;
    gcry_error_t rc;

    xmlSecAssert2(params != NULL, -1);
    xmlSecAssert2(mpis != NULL, -1);
    xmlSecAssert2(paramsNum == mpisNum, -1);

    for(ii = 0; ii < paramsNum; ++ii) {
        mpis[ii] = NULL;
        rc = gcry_mpi_scan(&(mpis[ii]), GCRYMPI_FMT_USG, params[ii].data, params[ii].size, NULL);
        if((rc != GPG_ERR_NO_ERROR) || (mpis[ii] == NULL)) {
            xmlSecGnuTLSGCryptError("gcry_mpi_scan", rc, NULL);
            xmlSecGnuTLSDestroyMpis(mpis, ii); /* destroy up to now */
            return(-1);
        }
    }

    /* done */
    return(0);
}


#ifndef XMLSEC_NO_RSA

/**
 * xmlSecGnuTLSKeyDataRsaGetKlass:
 *
 * The GnuTLS RSA key data klass.
 *
 * Returns: pointer to GnuTLS RSA key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataRsaGetKlass(void) {
    return (xmlSecGCryptKeyDataRsaGetKlass());
}

/**
 * xmlSecGnuTLSKeyDataRsaAdoptPrivateKey:
 * @data:               the pointer to RSA key data.
 * @rsa_key:            the pointer to GnuTLS RSA private key.
 *
 * Sets the value of RSA key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataRsaAdoptPrivateKey(xmlSecKeyDataPtr data, gnutls_x509_privkey_t rsa_key) {
    gnutls_datum_t params[6];
    gcry_mpi_t mpis[6];
    gcry_sexp_t privkey = NULL;
    gcry_sexp_t pubkey = NULL;
    gcry_error_t rc;
    int err;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), -1);
    xmlSecAssert2(rsa_key != NULL, -1);
    xmlSecAssert2(gnutls_x509_privkey_get_pk_algorithm(rsa_key) == GNUTLS_PK_RSA, -1);

    /* get raw values */
    err = gnutls_x509_privkey_export_rsa_raw(rsa_key,
            &(params[0]), &(params[1]), &(params[2]),
            &(params[3]), &(params[4]), &(params[5]));
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_x509_privkey_export_rsa_raw", err, NULL);
        return(-1);
    }

    /* convert to mpis */
    ret = xmlSecGnuTLSConvertParamsToMpis(
            params, sizeof(params)/sizeof(params[0]),
            mpis, sizeof(mpis)/sizeof(mpis[0]));
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSConvertParamsToMpis", NULL);
        xmlSecGnuTLSDestroyParams(params, sizeof(params)/sizeof(params[0]));
        return(-1);
    }
    xmlSecGnuTLSDestroyParams(params, sizeof(params)/sizeof(params[0]));

    /** Ignore p, q, u completely because optimized RSA encryption/decryption looks broken */
    /* Convert from OpenSSL parameter ordering to the OpenPGP order. */
    /* (http://gnupg.10057.n7.nabble.com/RSA-PKCS-1-signing-differs-from-OpenSSL-s-td27920.html) */
    /* First check that p < q; if not swap p and q and recompute u.  */
    /*
    if (gcry_mpi_cmp(mpis[3], mpis[4]) > 0) {
        gcry_mpi_swap(mpis[3], mpis[4]);
        gcry_mpi_invm(mpis[5], mpis[3], mpis[4]);
    }
    */

    /* build expressions */
    rc = gcry_sexp_build(&(privkey), NULL, "(private-key(rsa((n%m)(e%m)(d%m))))",
                        mpis[0], mpis[1], mpis[2]);
    if((rc != GPG_ERR_NO_ERROR) || (privkey == NULL)) {
        xmlSecGnuTLSGCryptError("gcry_sexp_build(private/rsa)", rc, NULL);
        xmlSecGnuTLSDestroyMpis(mpis, sizeof(mpis)/sizeof(mpis[0]));
        return(-1);
    }
    rc = gcry_sexp_build(&(pubkey), NULL, "(public-key(rsa((n%m)(e%m))))",
                        mpis[0], mpis[1]);
    if((rc != GPG_ERR_NO_ERROR) || (pubkey == NULL)) {
        xmlSecGnuTLSGCryptError("gcry_sexp_build(public/rsa)", rc, NULL);
        gcry_sexp_release(privkey);
        xmlSecGnuTLSDestroyMpis(mpis, sizeof(mpis)/sizeof(mpis[0]));
        return(-1);
    }
    xmlSecGnuTLSDestroyMpis(mpis, sizeof(mpis)/sizeof(mpis[0]));

    ret = xmlSecGCryptKeyDataRsaAdoptKeyPair(data, pubkey, privkey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptKeyDataRsaAdoptKeyPair", NULL);
        gcry_sexp_release(pubkey);
        gcry_sexp_release(privkey);
        return(-1);
    }

    /* done, we "adopted" the key - destroy it! */
    gnutls_x509_privkey_deinit(rsa_key);
    return(0);
}


/**
 * xmlSecGnuTLSKeyDataRsaAdoptPublicKey:
 * @data:               the pointer to RSA key data.
 * @m:                  the pointer to m component of the RSA public key
 * @e:                  the pointer to e component of the RSA public key
 *
 * Sets the value of RSA key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataRsaAdoptPublicKey(xmlSecKeyDataPtr data,
                                     gnutls_datum_t * m, gnutls_datum_t * e) {
    gnutls_datum_t params[2];
    gcry_mpi_t mpis[2];
    gcry_sexp_t pubkey = NULL;
    gcry_error_t rc;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), -1);
    xmlSecAssert2(m != NULL, -1);
    xmlSecAssert2(e != NULL, -1);

    /* copy */
    memcpy(&(params[0]), m, sizeof(*m));
    memcpy(&(params[1]), e, sizeof(*e));

    /* convert to mpis */
    ret = xmlSecGnuTLSConvertParamsToMpis(
            params, sizeof(params)/sizeof(params[0]),
            mpis, sizeof(mpis)/sizeof(mpis[0]));
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSConvertParamsToMpis", NULL);
        /* don't destroy params - we got them from outside !!! */
        return(-1);
    }
    /* don't destroy params - we got them from outside !!! */

    /* build expressions */
    rc = gcry_sexp_build(&(pubkey), NULL, "(public-key(rsa((n%m)(e%m))))",
                        mpis[0], mpis[1]);
    if((rc != GPG_ERR_NO_ERROR) || (pubkey == NULL)) {
        xmlSecGnuTLSGCryptError("gcry_sexp_build(public/rsa)", rc, NULL);
        xmlSecGnuTLSDestroyMpis(mpis, sizeof(mpis)/sizeof(mpis[0]));
        return(-1);
    }
    xmlSecGnuTLSDestroyMpis(mpis, sizeof(mpis)/sizeof(mpis[0]));

    ret = xmlSecGCryptKeyDataRsaAdoptKeyPair(data, pubkey, NULL);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptKeyDataRsaAdoptKeyPair", NULL);
        gcry_sexp_release(pubkey);
        return(-1);
    }

    /* done, we "adopted" the key - destroy it! */
    gnutls_free(m->data);
    gnutls_free(e->data);
    return(0);
}
#endif /* XMLSEC_NO_RSA */
