/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Private/public keys implementation for GnuTLS.
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

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/gnutls/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "private.h"

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
 * GnuTLS asym key data (dsa/rsa/ec)
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

gnutls_pubkey_t
xmlSecGnuTLSAsymKeyDataGetPublicKey(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), NULL);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->pubkey);
}

gnutls_privkey_t
xmlSecGnuTLSAsymKeyDataGetPrivateKey(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSAsymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecGnuTLSAsymKeyDataSize), NULL);

    ctx = xmlSecGnuTLSAsymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->privkey);
}

xmlSecKeyDataType
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

xmlSecSize
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

/********************************************************************
 *
 * Asymetric keys helpers
 *
 *******************************************************************/

/**
 * xmlSecGCryptAsymetricKeyCreatePub:
 * @pubkey:             the pointer to GnuTLS public key.
 *
 * Creates XMLSec key from GnuTLS public key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
xmlSecKeyPtr
xmlSecGCryptAsymetricKeyCreatePub(gnutls_pubkey_t pubkey) {
    xmlSecKeyDataPtr keyData;
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(pubkey != NULL, NULL);

    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", NULL);
        return(NULL);
    }

    keyData = xmlSecGnuTLSAsymKeyDataCreate(pubkey, NULL);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecGnuTLSAsymKeyDataCreate", NULL);
        xmlSecKeyDestroy(key);
        return(NULL);
    }

    /* this call should never fail, otherwise we might
     * "double free" pubkey (it's owned by keyData and then caller)
     */
    ret = xmlSecKeySetValue(key, keyData);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", NULL);
        xmlSecKeyDataDestroy(keyData);
        xmlSecKeyDestroy(key);
        return(NULL);
    }

    /* done */
    return(key);
}


/**
 * xmlSecGCryptAsymetricKeyCreatePriv:
 * @privkey:             the pointer to GnuTLS private key.
 *
 * Creates XMLSec key from GnuTLS private key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
xmlSecKeyPtr
xmlSecGCryptAsymetricKeyCreatePriv(gnutls_privkey_t privkey) {
    xmlSecKeyDataPtr keyData;
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(privkey != NULL, NULL);

    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", NULL);
        return(NULL);
    }

    keyData = xmlSecGnuTLSAsymKeyDataCreate(NULL, privkey);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecGnuTLSAsymKeyDataCreate", NULL);
        xmlSecKeyDestroy(key);
        return(NULL);
    }

    /* this call should never fail, otherwise we might
     * "double free" privkey (it's owned by keyData and then caller)
     */
    ret = xmlSecKeySetValue(key, keyData);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", NULL);
        xmlSecKeyDataDestroy(keyData);
        xmlSecKeyDestroy(key);
        return(NULL);
    }

    /* done */
    return(key);
}


/**
 * xmlSecGCryptAsymetricKeyGetPub:
 * @key:             the pointer to XMLSec key.
 *
 * Gets GnuTLS public key from an XMLSec @key .
 *
 * Returns: GnuTLS public key on success or a NULL value otherwise.
 */
gnutls_pubkey_t
xmlSecGCryptAsymetricKeyGetPub(xmlSecKeyPtr key) {
    xmlSecKeyDataPtr keyData;

    xmlSecAssert2(key != NULL, NULL);

    keyData = xmlSecKeyGetValue(key);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecKeyGetValue", NULL);
        return(NULL);
    }

    return(xmlSecGnuTLSAsymKeyDataGetPublicKey(keyData));
}

/**
 * xmlSecGCryptAsymetricKeyGetPriv:
 * @key:             the pointer to XMLSec key.
 *
 * Gets GnuTLS private key from an XMLSec @key .
 *
 * Returns: GnuTLS private key on success or a NULL value otherwise.
 */
gnutls_privkey_t
xmlSecGCryptAsymetricKeyGetPriv(xmlSecKeyPtr key) {
    xmlSecKeyDataPtr keyData;

    xmlSecAssert2(key != NULL, NULL);

    keyData = xmlSecKeyGetValue(key);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecKeyGetValue", NULL);
        return(NULL);
    }

    return(xmlSecGnuTLSAsymKeyDataGetPrivateKey(keyData));
}



/**************************************************************************
 *
 * <dsig11:DEREncodedKeyValue /> processing
 *
 *************************************************************************/
static int                      xmlSecGnuTLSKeyDataDEREncodedKeyValueXmlRead(xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int                      xmlSecGnuTLSKeyDataDEREncodedKeyValueXmlWrite(xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);



static xmlSecKeyDataKlass xmlSecGnuTLSKeyDataDEREncodedKeyValueKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),

    /* data */
    xmlSecNameDEREncodedKeyValue,
    xmlSecKeyDataUsageKeyInfoNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, /* xmlSecKeyDataUsage usage; */
    NULL,                                       /* const xmlChar* href; */
    xmlSecNodeDEREncodedKeyValue,               /* const xmlChar* dataNodeName; */
    xmlSecDSig11Ns,                             /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    NULL,                                       /* xmlSecKeyDataInitializeMethod initialize; */
    NULL,                                       /* xmlSecKeyDataDuplicateMethod duplicate; */
    NULL,                                       /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    NULL,                                       /* xmlSecKeyDataGetTypeMethod getType; */
    NULL,                                       /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecGnuTLSKeyDataDEREncodedKeyValueXmlRead,     /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecGnuTLSKeyDataDEREncodedKeyValueXmlWrite,    /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    NULL,                                       /* xmlSecKeyDataDebugDumpMethod debugDump; */
    NULL,                                       /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSKeyDataDEREncodedKeyValueGetKlass:
 * The public key algorithm and value are DER-encoded in accordance with the value that would be used
 * in the Subject Public Key Info field of an X.509 certificate, per section 4.1.2.7 of [RFC5280].
 * The DER-encoded value is then base64-encoded.
 *
 * https://www.w3.org/TR/xmldsig-core1/#sec-DEREncodedKeyValue
 *
 *      <!-- targetNamespace="http://www.w3.org/2009/xmldsig11#" -->
 *      <element name="DEREncodedKeyValue" type="dsig11:DEREncodedKeyValueType" />
 *      <complexType name="DEREncodedKeyValueType">
 *          <simpleContent>
 *              <extension base="base64Binary">
 *                  <attribute name="Id" type="ID" use="optional"/>
 *              </extension>
 *          </simpleContent>
 *      </complexType>
 *
 * Returns: the &lt;dsig11:DEREncodedKeyValue/&gt;element processing key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataDEREncodedKeyValueGetKlass(void) {
    return(&xmlSecGnuTLSKeyDataDEREncodedKeyValueKlass);
}

static int
xmlSecGnuTLSKeyDataDEREncodedKeyValueXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecBuffer buffer;
    const xmlSecByte * data;
    xmlSecSize dataSize;
    gnutls_datum_t datum;
    gnutls_pubkey_t pubkey = NULL;
    xmlSecKeyDataPtr keyData = NULL;
    xmlNodePtr cur;
    int res = -1;
    int err;
    int ret;

    xmlSecAssert2(id == xmlSecGnuTLSKeyDataDEREncodedKeyValueId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(node->doc != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->mode == xmlSecKeyInfoModeRead, -1);

    ret = xmlSecBufferInitialize(&buffer, 256);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    /* no children are expected */
    cur = xmlSecGetNextElementNode(node->children);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* read base64 node content */
    ret = xmlSecBufferBase64NodeContentRead(&buffer, node);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentRead", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    data = xmlSecBufferGetData(&buffer);
    dataSize = xmlSecBufferGetSize(&buffer);
    if((data == NULL) || (dataSize <= 0)) {
        /* this is not an error if we are reading a doc to be encrypted or signed */
        res = 0;
        goto done;
    }

    /* read pubkey */
	err = gnutls_pubkey_init(&pubkey);
	if(err < 0) {
        xmlSecGnuTLSError("gnutls_pubkey_init", err, xmlSecKeyDataKlassGetName(id));
        goto done;
	}

    datum.data = (xmlSecByte*)data; /* for const */
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(dataSize, datum.size, goto done, xmlSecKeyDataKlassGetName(id));

	err = gnutls_pubkey_import(pubkey, &datum, GNUTLS_X509_FMT_DER);
	if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_init", err, xmlSecKeyDataKlassGetName(id));
        goto done;
	}

    /* add to key */
    keyData = xmlSecGnuTLSAsymKeyDataCreate(pubkey, NULL);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecGnuTLSAsymKeyDataCreate", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    pubkey = NULL; /* owned by key data now */

    ret = xmlSecKeySetValue(key, keyData);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    keyData = NULL; /* owned by key now */

    /* success! */
    res = 0;

done:
    if(keyData != NULL) {
        xmlSecKeyDataDestroy(keyData);
    }
    if(pubkey != NULL) {
        gnutls_pubkey_deinit(pubkey);
    }
    xmlSecBufferFinalize(&buffer);
    return(res);
}

static int
xmlSecGnuTLSKeyDataDEREncodedKeyValueXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    gnutls_pubkey_t pubkey;
    gnutls_datum_t datum = { NULL, 0 };
    xmlChar* content = NULL;
    int err;
    int res = -1;

    xmlSecAssert2(id == xmlSecGnuTLSKeyDataDEREncodedKeyValueId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->mode == xmlSecKeyInfoModeWrite, -1);

    /* get pubkey */
    pubkey = xmlSecGCryptAsymetricKeyGetPub(key);
    if(pubkey == NULL) {
        xmlSecInternalError("xmlSecGCryptAsymetricKeyGetPub", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* encode it */
    err = gnutls_pubkey_export2(pubkey, GNUTLS_X509_FMT_DER, &datum);
	if((err != GNUTLS_E_SUCCESS) || (datum.data == NULL) || (datum.size <= 0)) {
        xmlSecGnuTLSError("gnutls_pubkey_export2", err, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* write to XML */
    content = xmlSecBase64Encode(datum.data, datum.size, xmlSecBase64GetDefaultLineSize());
    if(content == NULL) {
        xmlSecInternalError("xmlSecBase64Encode", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    xmlNodeAddContent(node, content);

    /* success */
    res = 0;

done:
    if(content != NULL) {
        xmlFree(content);
    }
    if(datum.data != NULL) {
        gnutls_free(datum.data);
    }
    return(res);
}


#ifndef XMLSEC_NO_DSA
/**************************************************************************
 *
 * &lt;dsig:DSAKeyValue/&gt; processing
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

static gnutls_pubkey_t  xmlSecGnuTLSKeyDataDsaPubKeyFromPrivKey (gnutls_privkey_t privkey);

static xmlSecKeyDataKlass xmlSecGnuTLSKeyDataDsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecGnuTLSAsymKeyDataSize,

    /* data */
    xmlSecNameDSAKeyValue,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
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
        pubkey = xmlSecGnuTLSKeyDataDsaPubKeyFromPrivKey(privkey);
        if(pubkey == NULL) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataDsaPubKeyFromPrivKey", NULL);
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
    if((y.data == NULL) || (y.size <= 0)) {
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
xmlSecGnuTLSKeyDataDsaPubKeyFromPrivKey(gnutls_privkey_t privkey) {
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


#ifndef XMLSEC_NO_EC
/**************************************************************************
 *
 * EC XML key representation processing.
 *
 *************************************************************************/

static int              xmlSecGnuTLSKeyDataEcInitialize         (xmlSecKeyDataPtr data);
static int              xmlSecGnuTLSKeyDataEcDuplicate          (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
static void             xmlSecGnuTLSKeyDataEcFinalize           (xmlSecKeyDataPtr data);

static xmlSecKeyDataType xmlSecGnuTLSKeyDataEcGetType           (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecGnuTLSKeyDataEcGetSize            (xmlSecKeyDataPtr data);

static int              xmlSecGnuTLSKeyDataEcXmlRead            (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecGnuTLSKeyDataEcXmlWrite           (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyDataPtr xmlSecGnuTLSKeyDataEcRead               (xmlSecKeyDataId id,
                                                                 xmlSecKeyValueEcPtr ecValue);
static int              xmlSecGnuTLSKeyDataEcWrite              (xmlSecKeyDataId id,
                                                                 xmlSecKeyDataPtr data,
                                                                 xmlSecKeyValueEcPtr ecValue);

static void             xmlSecGnuTLSKeyDataEcDebugDump          (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecGnuTLSKeyDataEcDebugXmlDump       (xmlSecKeyDataPtr data,
                                                                 FILE* output);

static gnutls_pubkey_t  xmlSecGnuTLSKeyDataEcPubKeyFromPrivKey  (gnutls_privkey_t privkey);

static xmlSecKeyDataKlass xmlSecGnuTLSKeyDataEcKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecGnuTLSAsymKeyDataSize,

    /* data */
    xmlSecNameECKeyValue,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefECKeyValue,                       /* const xmlChar* href; */
    xmlSecNodeECKeyValue,                       /* const xmlChar* dataNodeName; */
    xmlSecDSig11Ns,                             /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecGnuTLSKeyDataEcInitialize,            /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecGnuTLSKeyDataEcDuplicate,             /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecGnuTLSKeyDataEcFinalize,              /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecGnuTLSKeyDataEcGetType,               /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecGnuTLSKeyDataEcGetSize,               /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecGnuTLSKeyDataEcXmlRead,               /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecGnuTLSKeyDataEcXmlWrite,              /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecGnuTLSKeyDataEcDebugDump,             /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecGnuTLSKeyDataEcDebugXmlDump,          /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSKeyDataEcGetKlass:
 *
 * The GnuTLS EC key data klass.
 *
 * Returns: pointer to GnuTLS EC key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataEcGetKlass(void) {
    return(&xmlSecGnuTLSKeyDataEcKlass);
}

/**
 * xmlSecGnuTLSKeyDataEcAdoptKey:
 * @data:               the pointer to EC key data.
 * @pubkey:             the pointer to GnuTLS EC key.
 * @privkey:            the pointer to GnuTLS EC key.
 *
 * Sets the value of EC key data. The @pubkey and @privkey will be owned by the @data on success.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataEcAdoptKey(xmlSecKeyDataPtr data, gnutls_pubkey_t pubkey, gnutls_privkey_t privkey) {
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataEcId), -1);

    /* verify key type */
    if(pubkey != NULL) {
        ret = gnutls_pubkey_get_pk_algorithm(pubkey, NULL);
        if(ret != GNUTLS_PK_ECDSA) {
            xmlSecInternalError2("Invalid pubkey algorithm", NULL, "type=%d", ret);
            return(-1);
        }
    }
    if(privkey != NULL) {
        ret = gnutls_privkey_get_pk_algorithm(privkey, NULL);
        if(ret != GNUTLS_PK_ECDSA) {
            xmlSecInternalError2("Invalid privkey algorithm", NULL, "type=%d", ret);
            return(-1);
        }
    }

    /* create pub key if needed */
    if((privkey != NULL) && (pubkey == NULL)) {
        pubkey = xmlSecGnuTLSKeyDataEcPubKeyFromPrivKey(privkey);
        if(pubkey == NULL) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataEcPubKeyFromPrivKey", NULL);
            return(-1);
        }
    }

    /* do the work */
    return xmlSecGnuTLSAsymKeyDataAdoptKey(data, pubkey, privkey);
}

/**
 * xmlSecGnuTLSKeyDataEcGetPublicKey:
 * @data:               the pointer to EC key data.
 *
 * Gets the GnuTLS EC public key from EC key data.
 *
 * Returns: pointer to GnuTLS public EC key or NULL if an error occurs.
 */
gnutls_pubkey_t
xmlSecGnuTLSKeyDataEcGetPublicKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataEcId), NULL);
    return xmlSecGnuTLSAsymKeyDataGetPublicKey(data);
}

/**
 * xmlSecGnuTLSKeyDataEcGetPrivateKey:
 * @data:               the pointer to EC key data.
 *
 * Gets the GnuTLS EC private key from EC key data.
 *
 * Returns: pointer to GnuTLS private EC key or NULL if an error occurs.
 */
gnutls_privkey_t
xmlSecGnuTLSKeyDataEcGetPrivateKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataEcId), NULL);
    return xmlSecGnuTLSAsymKeyDataGetPrivateKey(data);
}

static int
xmlSecGnuTLSKeyDataEcInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataEcId), -1);

    return(xmlSecGnuTLSAsymKeyDataInitialize(data));
}

static int
xmlSecGnuTLSKeyDataEcDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecGnuTLSKeyDataEcId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecGnuTLSKeyDataEcId), -1);

    return(xmlSecGnuTLSAsymKeyDataDuplicate(dst, src));
}

static void
xmlSecGnuTLSKeyDataEcFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataEcId));

    xmlSecGnuTLSAsymKeyDataFinalize(data);
}

static xmlSecKeyDataType
xmlSecGnuTLSKeyDataEcGetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataEcId), xmlSecKeyDataTypeUnknown);

    return xmlSecGnuTLSAsymKeyDataGetType(data);
}

static xmlSecSize
xmlSecGnuTLSKeyDataEcGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataEcId), 0);

    return xmlSecGnuTLSAsymKeyDataGetSize(data);
}

static void
xmlSecGnuTLSKeyDataEcDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataEcId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== EC key: size = " XMLSEC_SIZE_FMT "\n",
            xmlSecGnuTLSKeyDataEcGetSize(data));
}

static void
xmlSecGnuTLSKeyDataEcDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataEcId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<ECKeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
            xmlSecGnuTLSKeyDataEcGetSize(data));
}

static int
xmlSecGnuTLSKeyDataEcXmlRead(xmlSecKeyDataId id,
                              xmlSecKeyPtr key,
                              xmlNodePtr node,
                              xmlSecKeyInfoCtxPtr keyInfoCtx)
{
    xmlSecAssert2(id == xmlSecGnuTLSKeyDataEcId, -1);
    return(xmlSecKeyDataEcXmlRead(id, key, node, keyInfoCtx,
        xmlSecGnuTLSKeyDataEcRead));
}

static int
xmlSecGnuTLSKeyDataEcXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecGnuTLSKeyDataEcId, -1);
    return(xmlSecKeyDataEcXmlWrite(id, key, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecGnuTLSKeyDataEcWrite));
}

static xmlSecKeyDataPtr
xmlSecGnuTLSKeyDataEcRead(xmlSecKeyDataId id, xmlSecKeyValueEcPtr ecValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    xmlSecSize size;
    gnutls_ecc_curve_t curve;
	gnutls_datum_t pub_x, pub_y;
    gnutls_pubkey_t pubkey = NULL;
    int err;
    int ret;

    xmlSecAssert2(id == xmlSecGnuTLSKeyDataEcId, NULL);
    xmlSecAssert2(ecValue != NULL, NULL);
    xmlSecAssert2(ecValue->curve != NULL, NULL);

    /* we need individual public key components x and y */
    ret = xmlSecKeyDataEcPublicKeySplitComponents(ecValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyDataEcPublicKeySplitComponents",  xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    curve = gnutls_oid_to_ecc_curve((const char*)ecValue->curve);
    if(curve == GNUTLS_ECC_CURVE_INVALID) {
        xmlSecGnuTLSError2("gnutls_oid_to_ecc_curve", GNUTLS_E_SUCCESS, xmlSecKeyDataKlassGetName(id),
            "curve oid=%s", xmlSecErrorsSafeString(ecValue->curve));
        goto done;
    }

    /*** pub: x ***/
    size = xmlSecBufferGetSize(&(ecValue->pub_x));
    pub_x.data = xmlSecBufferGetData(&(ecValue->pub_x));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, pub_x.size,  goto done, xmlSecKeyDataKlassGetName(id));

    /*** pub: y ***/
    size = xmlSecBufferGetSize(&(ecValue->pub_y));
    pub_y.data = xmlSecBufferGetData(&(ecValue->pub_y));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, pub_y.size,  goto done, xmlSecKeyDataKlassGetName(id));

    /* pub key */
    err = gnutls_pubkey_init(&pubkey);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_init", err, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    err = gnutls_pubkey_import_ecc_raw(pubkey, curve, &pub_x, &pub_y);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_import_ecc_raw", err, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* create key data */
    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
        xmlSecInternalError("xmlSecKeyDataCreate", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecGnuTLSKeyDataEcAdoptKey(data, pubkey, NULL);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSKeyDataEcAdoptKey", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    pubkey = NULL; /* pubkey is owned by data now */

    /* success */
    res = data;
    data = NULL;

done:
    /* cleanup */
    if(pubkey != NULL) {
        gnutls_pubkey_deinit(pubkey);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

static int
xmlSecGnuTLSKeyDataEcWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data, xmlSecKeyValueEcPtr ecValue)
{
    gnutls_privkey_t privkey = NULL;
    gnutls_pubkey_t pubkey = NULL;
    gnutls_ecc_curve_t curve = GNUTLS_ECC_CURVE_INVALID;
	gnutls_datum_t pub_x = { NULL, 0 };
    gnutls_datum_t pub_y = { NULL, 0 };
    const char * curve_oid;
    int ret;
    int err;
    int res = -1;

    xmlSecAssert2(id == xmlSecGnuTLSKeyDataEcId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataEcId), -1);
    xmlSecAssert2(ecValue != NULL, -1);

    /* get components */
    privkey = xmlSecGnuTLSKeyDataEcGetPrivateKey(data);
    pubkey = xmlSecGnuTLSKeyDataEcGetPublicKey(data);
    if(privkey != NULL) {
        err = gnutls_privkey_export_ecc_raw2(privkey,
                &curve, &pub_x, &pub_y, NULL,
                GNUTLS_EXPORT_FLAG_NO_LZ);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_privkey_export_ec_raw2", err, xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    } else if(pubkey != NULL) {
        err = gnutls_pubkey_export_ecc_raw2(pubkey,
			       &curve, &pub_x, &pub_y,
                   GNUTLS_EXPORT_FLAG_NO_LZ);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_pubkey_export_ec_raw2", err, xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    } else {
        xmlSecInternalError("Neither private or public keys are available", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* curve */
    if(curve == GNUTLS_ECC_CURVE_INVALID) {
        xmlSecInternalError("EC curve is invalid", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    curve_oid = gnutls_ecc_curve_get_oid(curve);
    if(curve_oid == NULL) {
        xmlSecGnuTLSError("gnutls_ecc_curve_get_oid", GNUTLS_E_SUCCESS, xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ecValue->curve = xmlStrdup(BAD_CAST curve_oid);
    if(ecValue->curve == NULL) {
        xmlSecStrdupError(BAD_CAST curve_oid, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* pub: x */
    if((pub_x.data == NULL) || (pub_x.size <= 0)) {
        xmlSecInternalError("EC pub x parameter is NULL", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = xmlSecBufferAppend(&(ecValue->pub_x), pub_x.data, pub_x.size);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(pub_x)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* pub: y */
    if((pub_y.data == NULL) || (pub_y.size <= 0)) {
        xmlSecInternalError("EC pub y parameter is NULL", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = xmlSecBufferAppend(&(ecValue->pub_y), pub_y.data, pub_y.size);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(pub_y)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecKeyDataEcPublicKeyCombineComponents(ecValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyDataEcPublicKeyCombineComponents",  xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* success */
    res = 0;

done:
    if(pub_x.data != NULL) {
        gnutls_free(pub_x.data);
    }
    if(pub_y.data != NULL) {
        gnutls_free(pub_y.data);
    }
    return(res);
}

static gnutls_pubkey_t
xmlSecGnuTLSKeyDataEcPubKeyFromPrivKey(gnutls_privkey_t privkey) {
    gnutls_pubkey_t pubkey = NULL;
    gnutls_ecc_curve_t curve = GNUTLS_ECC_CURVE_INVALID;
	gnutls_datum_t x = { NULL, 0 };
    gnutls_datum_t y = { NULL, 0 };
    gnutls_datum_t k = { NULL, 0 };
    int err;

    xmlSecAssert2(privkey != NULL, NULL);

    err = gnutls_privkey_export_ecc_raw2(privkey,
                &curve, &x, &y, &k,
                0);
    if((err != GNUTLS_E_SUCCESS) && (curve != GNUTLS_ECC_CURVE_INVALID)) {
        xmlSecGnuTLSError("gnutls_privkey_export_ecc_raw2", err, NULL);
        goto done;
    }

    err = gnutls_pubkey_init(&pubkey);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_init", err, NULL);
        goto done;
    }

    err = gnutls_pubkey_import_ecc_raw(pubkey, curve, &x, &y);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_import_ecc_raw", err, NULL);
        gnutls_pubkey_deinit(pubkey);
        goto done;
    }

done:
    if(x.data != NULL) {
        gnutls_free(x.data);
    }
    if(y.data != NULL) {
        gnutls_free(y.data);
    }
    if(k.data != NULL) {
        gnutls_free(k.data);
    }
    return(pubkey);
}

#endif /* XMLSEC_NO_EC */


#ifndef XMLSEC_NO_RSA
/**************************************************************************
 *
 * &lt;dsig:RSAKeyValue/&gt; processing
 *
 *
 * The RSAKeyValue Element (http://www.w3.org/TR/xmldsig-core/#sec-RSAKeyValue)
 *
 **************************************************************************/

static int              xmlSecGnuTLSKeyDataRsaInitialize        (xmlSecKeyDataPtr data);
static void             xmlSecGnuTLSKeyDataRsaFinalize          (xmlSecKeyDataPtr data);
static int              xmlSecGnuTLSKeyDataRsaGenerate          (xmlSecKeyDataPtr data,
                                                                 xmlSecSize sizeBits,
                                                                 xmlSecKeyDataType type);
static int              xmlSecGnuTLSKeyDataRsaDuplicate         (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);


static xmlSecKeyDataType xmlSecGnuTLSKeyDataRsaGetType          (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecGnuTLSKeyDataRsaGetSize           (xmlSecKeyDataPtr data);
static void             xmlSecGnuTLSKeyDataRsaDebugDump         (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecGnuTLSKeyDataRsaDebugXmlDump      (xmlSecKeyDataPtr data,
                                                                 FILE* output);

static int              xmlSecGnuTLSKeyDataRsaXmlRead           (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecGnuTLSKeyDataRsaXmlWrite          (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyDataPtr xmlSecGnuTLSKeyDataRsaRead              (xmlSecKeyDataId id,
                                                                 xmlSecKeyValueRsaPtr rsaValue);
static int              xmlSecGnuTLSKeyDataRsaWrite             (xmlSecKeyDataId id,
                                                                 xmlSecKeyDataPtr data,
                                                                 xmlSecKeyValueRsaPtr rsaValue,
                                                                 int writePrivateKey);

static gnutls_pubkey_t  xmlSecGnuTLSKeyDataRsaPubKeyFromPrivKey  (gnutls_privkey_t privkey);

static xmlSecKeyDataKlass xmlSecGnuTLSKeyDataRsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecGnuTLSAsymKeyDataSize,

    /* data */
    xmlSecNameRSAKeyValue,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefRSAKeyValue,                      /* const xmlChar* href; */
    xmlSecNodeRSAKeyValue,                      /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecGnuTLSKeyDataRsaInitialize,          /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecGnuTLSKeyDataRsaDuplicate,           /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecGnuTLSKeyDataRsaFinalize,            /* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecGnuTLSKeyDataRsaGenerate,            /* xmlSecKeyDatavMethod generate; */

    /* get info */
    xmlSecGnuTLSKeyDataRsaGetType,              /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecGnuTLSKeyDataRsaGetSize,              /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecGnuTLSKeyDataRsaXmlRead,              /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecGnuTLSKeyDataRsaXmlWrite,             /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
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
 * The RSA key data klass.
 *
 * Returns: pointer to RSA key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataRsaGetKlass(void) {
    return(&xmlSecGnuTLSKeyDataRsaKlass);
}

/**
 * xmlSecGnuTLSKeyDataRsaAdoptKey:
 * @data:               the pointer to RSA key data.
 * @pubkey:             the pointer to GnuTLS RSA key.
 * @privkey:            the pointer to GnuTLS RSA key.
 *
 * Sets the value of RSA key data. The @pubkey and @privkey will be owned by the @data on success.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataRsaAdoptKey(xmlSecKeyDataPtr data, gnutls_pubkey_t pubkey, gnutls_privkey_t privkey) {
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), -1);

    /* verify key type */
    if(pubkey != NULL) {
        ret = gnutls_pubkey_get_pk_algorithm(pubkey, NULL);
        if(ret != GNUTLS_PK_RSA) {
            xmlSecInternalError2("Invalid pubkey algorithm", NULL, "type=%d", ret);
            return(-1);
        }
    }
    if(privkey != NULL) {
        ret = gnutls_privkey_get_pk_algorithm(privkey, NULL);
        if(ret != GNUTLS_PK_RSA) {
            xmlSecInternalError2("Invalid privkey algorithm", NULL, "type=%d", ret);
            return(-1);
        }
    }

    /* create pub key if needed */
    if((privkey != NULL) && (pubkey == NULL)) {
        pubkey = xmlSecGnuTLSKeyDataRsaPubKeyFromPrivKey(privkey);
        if(pubkey == NULL) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataRsaPubKeyFromPrivKey", NULL);
            return(-1);
        }
    }

    /* do the work */
    return xmlSecGnuTLSAsymKeyDataAdoptKey(data, pubkey, privkey);
}

/**
 * xmlSecGnuTLSKeyDataRsaGetPublicKey:
 * @data:               the pointer to RSA key data.
 *
 * Gets the GnuTLS RSA public key from RSA key data.
 *
 * Returns: pointer to GnuTLS public RSA key or NULL if an error occurs.
 */
gnutls_pubkey_t
xmlSecGnuTLSKeyDataRsaGetPublicKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), NULL);
    return xmlSecGnuTLSAsymKeyDataGetPublicKey(data);
}

/**
 * xmlSecGnuTLSKeyDataRsaGetPrivateKey:
 * @data:               the pointer to RSA key data.
 *
 * Gets the GnuTLS RSA private key from RSA key data.
 *
 * Returns: pointer to GnuTLS private RSA key or NULL if an error occurs.
 */
gnutls_privkey_t
xmlSecGnuTLSKeyDataRsaGetPrivateKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), NULL);
    return xmlSecGnuTLSAsymKeyDataGetPrivateKey(data);
}

static int
xmlSecGnuTLSKeyDataRsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), -1);

    return(xmlSecGnuTLSAsymKeyDataInitialize(data));
}

static void
xmlSecGnuTLSKeyDataRsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId));

    xmlSecGnuTLSAsymKeyDataFinalize(data);
}

static int
xmlSecGnuTLSKeyDataRsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecGnuTLSKeyDataRsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecGnuTLSKeyDataRsaId), -1);

    return(xmlSecGnuTLSAsymKeyDataDuplicate(dst, src));
}

static int
xmlSecGnuTLSKeyDataRsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    return xmlSecGnuTLSAsymKeyDataGenerate(data, GNUTLS_PK_RSA, sizeBits);
}

static xmlSecKeyDataType
xmlSecGnuTLSKeyDataRsaGetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), xmlSecKeyDataTypeUnknown);

    return xmlSecGnuTLSAsymKeyDataGetType(data);
}

static xmlSecSize
xmlSecGnuTLSKeyDataRsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), 0);

    return xmlSecGnuTLSAsymKeyDataGetSize(data);
}

static void
xmlSecGnuTLSKeyDataRsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== rsa key: size = " XMLSEC_SIZE_FMT "\n",
            xmlSecGnuTLSKeyDataRsaGetSize(data));
}

static void
xmlSecGnuTLSKeyDataRsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<RSAKeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
            xmlSecGnuTLSKeyDataRsaGetSize(data));
}

static int
xmlSecGnuTLSKeyDataRsaXmlRead(xmlSecKeyDataId id,
                              xmlSecKeyPtr key,
                              xmlNodePtr node,
                              xmlSecKeyInfoCtxPtr keyInfoCtx)
{
    xmlSecAssert2(id == xmlSecGnuTLSKeyDataRsaId, -1);
    return(xmlSecKeyDataRsaXmlRead(id, key, node, keyInfoCtx,
        xmlSecGnuTLSKeyDataRsaRead));
}

static int
xmlSecGnuTLSKeyDataRsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecGnuTLSKeyDataRsaId, -1);
    return(xmlSecKeyDataRsaXmlWrite(id, key, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecGnuTLSKeyDataRsaWrite));
}

static xmlSecKeyDataPtr
xmlSecGnuTLSKeyDataRsaRead(xmlSecKeyDataId id, xmlSecKeyValueRsaPtr rsaValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    xmlSecSize size;
	gnutls_datum_t modulus, publicExponent;
    gnutls_pubkey_t pubkey = NULL;
    int err;
    int ret;

    xmlSecAssert2(id == xmlSecGnuTLSKeyDataRsaId, NULL);
    xmlSecAssert2(rsaValue != NULL, NULL);

    /*** modulus ***/
    size = xmlSecBufferGetSize(&(rsaValue->modulus));
    modulus.data = xmlSecBufferGetData(&(rsaValue->modulus));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, modulus.size,  goto done, xmlSecKeyDataKlassGetName(id));

    /*** publicExponent ***/
    size = xmlSecBufferGetSize(&(rsaValue->publicExponent));
    publicExponent.data = xmlSecBufferGetData(&(rsaValue->publicExponent));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, publicExponent.size,  goto done, xmlSecKeyDataKlassGetName(id));

    /*** privateExponent (only for private key) ***/
    size = xmlSecBufferGetSize(&(rsaValue->privateExponent));
    if(size > 0) {
        xmlSecGnuTLSError("GnuTLS doesn't support reading private keys from RSAKeyValue", GNUTLS_E_SUCCESS, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* pub key */
    err = gnutls_pubkey_init(&pubkey);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_init", err, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    err = gnutls_pubkey_import_rsa_raw(pubkey,
            &modulus,           /* m */
            &publicExponent     /* e */
    );
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_import_rsa_raw", err, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* create key data */
    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
        xmlSecInternalError("xmlSecKeyDataCreate", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecGnuTLSKeyDataRsaAdoptKey(data, pubkey, NULL);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSKeyDataRsaAdoptKey", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    pubkey = NULL; /* pubkey is owned by data now */

    /* success */
    res = data;
    data = NULL;

done:
    /* cleanup */
    if(pubkey != NULL) {
        gnutls_pubkey_deinit(pubkey);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

static int
xmlSecGnuTLSKeyDataRsaWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data,
    xmlSecKeyValueRsaPtr rsaValue, int writePrivateKey)
{
    gnutls_privkey_t privkey = NULL;
    gnutls_pubkey_t pubkey = NULL;
	gnutls_datum_t modulus = { NULL, 0 };
    gnutls_datum_t publicExponent = { NULL, 0 };
    gnutls_datum_t privateExponent = { NULL, 0 };
    int ret;
    int err;
    int res = -1;

    xmlSecAssert2(id == xmlSecGnuTLSKeyDataRsaId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), -1);
    xmlSecAssert2(rsaValue != NULL, -1);

    /* get components */
    privkey = xmlSecGnuTLSKeyDataRsaGetPrivateKey(data);
    pubkey = xmlSecGnuTLSKeyDataRsaGetPublicKey(data);
    if(privkey != NULL) {
        err = gnutls_privkey_export_rsa_raw2(privkey,
                    &modulus,           /* m */
                    &publicExponent,    /* e */
                    &privateExponent,   /* d */
                    NULL,               /* p */
                    NULL,               /* q */
                    NULL,               /* u */
                    NULL,               /* e1 */
                    NULL,               /* e2 */
                    GNUTLS_EXPORT_FLAG_NO_LZ);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_privkey_export_rsa_raw2", err, xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    } else if(pubkey != NULL) {
        err = gnutls_pubkey_export_rsa_raw2(pubkey,
                    &modulus,           /* m */
                    &publicExponent,    /* e */
                   GNUTLS_EXPORT_FLAG_NO_LZ);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_pubkey_export_rsa_raw2", err, xmlSecKeyDataKlassGetName(id));
            goto done;
        }
    } else {
        xmlSecInternalError("Neither private or public keys are available", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* modulus */
    if((modulus.data == NULL) || (modulus.size <= 0)) {
        xmlSecInternalError("RSA modulus parameter is NULL", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = xmlSecBufferAppend(&(rsaValue->modulus), modulus.data, modulus.size);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(modulus)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* publicExponent */
    if((publicExponent.data == NULL) || (publicExponent.size <= 0)) {
        xmlSecInternalError("RSA publicExponent parameter is NULL", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = xmlSecBufferAppend(&(rsaValue->publicExponent), publicExponent.data, publicExponent.size);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(publicExponent)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /*** GnuTLS doesn't support private exponent  ***/
    if((writePrivateKey != 0) && (privkey != NULL)) {
        /* do nothing */
    }

    /* success */
    res = 0;

done:
    if(modulus.data != NULL) {
        gnutls_free(modulus.data);
    }
    if(publicExponent.data != NULL) {
        gnutls_free(publicExponent.data);
    }
    if(privateExponent.data != NULL) {
        gnutls_free(privateExponent.data);
    }

    return(res);
}

static gnutls_pubkey_t
xmlSecGnuTLSKeyDataRsaPubKeyFromPrivKey(gnutls_privkey_t privkey) {
    gnutls_pubkey_t pubkey = NULL;
	gnutls_datum_t modulus = { NULL, 0 };
    gnutls_datum_t publicExponent = { NULL, 0 };
    gnutls_datum_t privateExponent = { NULL, 0 };
    gnutls_datum_t p = { NULL, 0 };
    gnutls_datum_t q = { NULL, 0 };
    int err;

    xmlSecAssert2(privkey != NULL, NULL);

    err = gnutls_privkey_export_rsa_raw2(privkey,
                &modulus,           /* m */
                &publicExponent,    /* e */
                &privateExponent,   /* d */
                &p,                 /* p */
                &q,                 /* q */
                NULL,               /* u */
                NULL,               /* e1 */
                NULL,               /* e2 */
                0);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_privkey_export_rsa_raw2", err, NULL);
        goto done;
    }

    err = gnutls_pubkey_init(&pubkey);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_init", err, NULL);
        goto done;
    }

    err = gnutls_pubkey_import_rsa_raw(pubkey,
                &modulus,           /* m */
                &publicExponent     /* e */
    );
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_import_rsa_raw", err, NULL);
        gnutls_pubkey_deinit(pubkey);
        goto done;
    }

done:
    if(modulus.data != NULL) {
        gnutls_free(modulus.data);
    }
    if(publicExponent.data != NULL) {
        gnutls_free(publicExponent.data);
    }
    if(privateExponent.data != NULL) {
        gnutls_free(privateExponent.data);
    }
    if(p.data != NULL) {
        gnutls_free(p.data);
    }
    if(q.data != NULL) {
        gnutls_free(q.data);
    }
    return(pubkey);
}

#endif /* XMLSEC_NO_RSA */

/**************************************************************************
 *
 * Shared GOST2001 and GOST2012 keys functions
 *
 *************************************************************************/

#if !defined(XMLSEC_NO_GOST) || !defined(XMLSEC_NO_GOST2012)
static gnutls_pubkey_t
xmlSecGnuTLSKeyDataGostPubKeyFromPrivKey(gnutls_privkey_t privkey) {
    gnutls_pubkey_t pubkey = NULL;
    gnutls_ecc_curve_t curve = GNUTLS_ECC_CURVE_INVALID;
    gnutls_digest_algorithm_t digest = GNUTLS_DIG_UNKNOWN;
    gnutls_gost_paramset_t paramset = GNUTLS_GOST_PARAMSET_UNKNOWN;
	gnutls_datum_t x = { NULL, 0 };
    gnutls_datum_t y = { NULL, 0 };
    gnutls_datum_t k = { NULL, 0 };
    int err;

    xmlSecAssert2(privkey != NULL, NULL);

    err = gnutls_privkey_export_gost_raw2(privkey,
        &curve, &digest, &paramset,
        &x, &y, &k,
        0);
    if((err != GNUTLS_E_SUCCESS) && (curve != GNUTLS_ECC_CURVE_INVALID)) {
        xmlSecGnuTLSError("gnutls_privkey_export_gost_raw2", err, NULL);
        goto done;
    }

    err = gnutls_pubkey_init(&pubkey);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_init", err, NULL);
        goto done;
    }

    err = gnutls_pubkey_import_gost_raw(pubkey,
        curve, digest, paramset,
        &x, &y);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_import_gost_raw", err, NULL);
        gnutls_pubkey_deinit(pubkey);
        goto done;
    }

done:
    if(x.data != NULL) {
        gnutls_free(x.data);
    }
    if(y.data != NULL) {
        gnutls_free(y.data);
    }
    if(k.data != NULL) {
        gnutls_free(k.data);
    }
    return(pubkey);
}

static int
xmlSecGnuTLSKeyDataGostAdoptKey(int algo, xmlSecKeyDataPtr data, gnutls_pubkey_t pubkey, gnutls_privkey_t privkey) {
    int ret;

    /* verify key type */
    if(pubkey != NULL) {
        ret = gnutls_pubkey_get_pk_algorithm(pubkey, NULL);
        if(ret != algo) {
            xmlSecInternalError2("Invalid pubkey algorithm", NULL, "type=%d", ret);
            return(-1);
        }
    }
    if(privkey != NULL) {
        ret = gnutls_privkey_get_pk_algorithm(privkey, NULL);
        if(ret != algo) {
            xmlSecInternalError2("Invalid privkey algorithm", NULL, "type=%d", ret);
            return(-1);
        }
    }

    /* create pub key if needed */
    if((privkey != NULL) && (pubkey == NULL)) {
        pubkey = xmlSecGnuTLSKeyDataGostPubKeyFromPrivKey(privkey);
        if(pubkey == NULL) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataGostPubKeyFromPrivKey", NULL);
            return(-1);
        }
    }

    /* do the work */
    return xmlSecGnuTLSAsymKeyDataAdoptKey(data, pubkey, privkey);
}
#endif /* !defined(XMLSEC_NO_GOST) || !defined(XMLSEC_NO_GOST2012) */

#ifndef XMLSEC_NO_GOST
/**************************************************************************
 *
 * GOST2001 XML key representation processing.
 *
 *************************************************************************/

static int              xmlSecGnuTLSKeyDataGost2001Initialize   (xmlSecKeyDataPtr data);
static int              xmlSecGnuTLSKeyDataGost2001Duplicate    (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
static void             xmlSecGnuTLSKeyDataGost2001Finalize     (xmlSecKeyDataPtr data);

static xmlSecKeyDataType xmlSecGnuTLSKeyDataGost2001GetType     (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecGnuTLSKeyDataGost2001GetSize      (xmlSecKeyDataPtr data);

static void             xmlSecGnuTLSKeyDataGost2001DebugDump    (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecGnuTLSKeyDataGost2001DebugXmlDump (xmlSecKeyDataPtr data,
                                                                 FILE* output);

static xmlSecKeyDataKlass xmlSecGnuTLSKeyDataGost2001Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecGnuTLSAsymKeyDataSize,

    /* data */
    xmlSecNameGOST2001KeyValue,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefGOST2001KeyValue,                 /* const xmlChar* href; */
    xmlSecNodeGOST2001KeyValue,                 /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecGnuTLSKeyDataGost2001Initialize,      /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecGnuTLSKeyDataGost2001Duplicate,       /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecGnuTLSKeyDataGost2001Finalize,        /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecGnuTLSKeyDataGost2001GetType,         /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecGnuTLSKeyDataGost2001GetSize,         /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,                                       /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,                                       /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecGnuTLSKeyDataGost2001DebugDump,       /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecGnuTLSKeyDataGost2001DebugXmlDump,    /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSKeyDataGost2001GetKlass:
 *
 * The GnuTLS GOST 2001 key data klass.
 *
 * Returns: pointer to GnuTLS GOST 2001 key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataGost2001GetKlass(void) {
    return(&xmlSecGnuTLSKeyDataGost2001Klass);
}

/**
 * xmlSecGnuTLSKeyDataGost2001AdoptKey:
 * @data:               the pointer to GOST 2001 key data.
 * @pubkey:             the pointer to GnuTLS GOST 2001 key.
 * @privkey:            the pointer to GnuTLS GOST 2001 key.
 *
 * Sets the value of GOST 2001 key data. The @pubkey and @privkey will be owned by the @data on success.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataGost2001AdoptKey(xmlSecKeyDataPtr data, gnutls_pubkey_t pubkey, gnutls_privkey_t privkey) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2001Id), -1);
    return(xmlSecGnuTLSKeyDataGostAdoptKey(GNUTLS_PK_GOST_01, data, pubkey, privkey));
}

/**
 * xmlSecGnuTLSKeyDataGost2001GetPublicKey:
 * @data:               the pointer to GOST 2001 key data.
 *
 * Gets the GnuTLS GOST 2001 public key from GOST 2001 key data.
 *
 * Returns: pointer to GnuTLS public GOST 2001 key or NULL if an error occurs.
 */
gnutls_pubkey_t
xmlSecGnuTLSKeyDataGost2001GetPublicKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2001Id), NULL);
    return xmlSecGnuTLSAsymKeyDataGetPublicKey(data);
}

/**
 * xmlSecGnuTLSKeyDataGost2001GetPrivateKey:
 * @data:               the pointer to GOST 2001 key data.
 *
 * Gets the GnuTLS GOST 2001 private key from GOST 2001 key data.
 *
 * Returns: pointer to GnuTLS private GOST 2001 key or NULL if an error occurs.
 */
gnutls_privkey_t
xmlSecGnuTLSKeyDataGost2001GetPrivateKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2001Id), NULL);
    return xmlSecGnuTLSAsymKeyDataGetPrivateKey(data);
}

static int
xmlSecGnuTLSKeyDataGost2001Initialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2001Id), -1);

    return(xmlSecGnuTLSAsymKeyDataInitialize(data));
}

static int
xmlSecGnuTLSKeyDataGost2001Duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecGnuTLSKeyDataGost2001Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecGnuTLSKeyDataGost2001Id), -1);

    return(xmlSecGnuTLSAsymKeyDataDuplicate(dst, src));
}

static void
xmlSecGnuTLSKeyDataGost2001Finalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2001Id));

    xmlSecGnuTLSAsymKeyDataFinalize(data);
}

static xmlSecKeyDataType
xmlSecGnuTLSKeyDataGost2001GetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2001Id), xmlSecKeyDataTypeUnknown);

    return xmlSecGnuTLSAsymKeyDataGetType(data);
}

static xmlSecSize
xmlSecGnuTLSKeyDataGost2001GetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2001Id), 0);

    return xmlSecGnuTLSAsymKeyDataGetSize(data);
}

static void
xmlSecGnuTLSKeyDataGost2001DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2001Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== GOST 2001 key: size = " XMLSEC_SIZE_FMT "\n",
            xmlSecGnuTLSKeyDataGost2001GetSize(data));
}

static void
xmlSecGnuTLSKeyDataGost2001DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2001Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<GOST2001KeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
            xmlSecGnuTLSKeyDataGost2001GetSize(data));
}

#endif /* XMLSEC_NO_GOST */



#ifndef XMLSEC_NO_GOST2012
/**************************************************************************
 *
 * GOST R 34.10-2012 256 bit xml key representation processing
 *
 *************************************************************************/
static int              xmlSecGnuTLSKeyDataGost2012_256Initialize   (xmlSecKeyDataPtr data);
static int              xmlSecGnuTLSKeyDataGost2012_256Duplicate    (xmlSecKeyDataPtr dst,
                                                                     xmlSecKeyDataPtr src);
static void             xmlSecGnuTLSKeyDataGost2012_256Finalize     (xmlSecKeyDataPtr data);

static xmlSecKeyDataType xmlSecGnuTLSKeyDataGost2012_256GetType     (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecGnuTLSKeyDataGost2012_256GetSize      (xmlSecKeyDataPtr data);

static void             xmlSecGnuTLSKeyDataGost2012_256DebugDump    (xmlSecKeyDataPtr data,
                                                                     FILE* output);
static void             xmlSecGnuTLSKeyDataGost2012_256DebugXmlDump (xmlSecKeyDataPtr data,
                                                                     FILE* output);

static xmlSecKeyDataKlass xmlSecGnuTLSKeyDataGost2012_256Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecGnuTLSAsymKeyDataSize,

    /* data */
    xmlSecNameGostR3410_2012_256KeyValue,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefGostR3410_2012_256KeyValue,       /* const xmlChar* href; */
    xmlSecNodeGostR3410_2012_256KeyValue,       /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecGnuTLSKeyDataGost2012_256Initialize,  /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecGnuTLSKeyDataGost2012_256Duplicate,   /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecGnuTLSKeyDataGost2012_256Finalize,    /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecGnuTLSKeyDataGost2012_256GetType,     /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecGnuTLSKeyDataGost2012_256GetSize,     /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,                                       /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,                                       /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecGnuTLSKeyDataGost2012_256DebugDump,       /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecGnuTLSKeyDataGost2012_256DebugXmlDump,    /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSKeyDataGost2012_256GetKlass:
 *
 * The GnuTLS GOST 2012 (256 bits) key data klass.
 *
 * Returns: pointer to GnuTLS GOST 2012 (256 bits) key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataGost2012_256GetKlass(void) {
    return(&xmlSecGnuTLSKeyDataGost2012_256Klass);
}

/**
 * xmlSecGnuTLSKeyDataGost2012_256AdoptKey:
 * @data:               the pointer to GOST 2012 (256 bits) key data.
 * @pubkey:             the pointer to GnuTLS GOST 2012 (256 bits) key.
 * @privkey:            the pointer to GnuTLS GOST 2012 (256 bits) key.
 *
 * Sets the value of GOST 2012 (256 bits) key data. The @pubkey and @privkey will be owned by the @data on success.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataGost2012_256AdoptKey(xmlSecKeyDataPtr data, gnutls_pubkey_t pubkey, gnutls_privkey_t privkey) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_256Id), -1);
    return(xmlSecGnuTLSKeyDataGostAdoptKey(GNUTLS_PK_GOST_12_256, data, pubkey, privkey));
}

/**
 * xmlSecGnuTLSKeyDataGost2012_256GetPublicKey:
 * @data:               the pointer to GOST 2012 (256 bits) key data.
 *
 * Gets the GnuTLS GOST 2012 (256 bits) public key from GOST 2012 (256 bits) key data.
 *
 * Returns: pointer to GnuTLS public GOST 2012 (256 bits) key or NULL if an error occurs.
 */
gnutls_pubkey_t
xmlSecGnuTLSKeyDataGost2012_256GetPublicKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_256Id), NULL);
    return xmlSecGnuTLSAsymKeyDataGetPublicKey(data);
}

/**
 * xmlSecGnuTLSKeyDataGost2012_256GetPrivateKey:
 * @data:               the pointer to GOST 2012 (256 bits) key data.
 *
 * Gets the GnuTLS GOST 2012 (256 bits) private key from GOST 2012 (256 bits) key data.
 *
 * Returns: pointer to GnuTLS private GOST 2012 (256 bits) key or NULL if an error occurs.
 */
gnutls_privkey_t
xmlSecGnuTLSKeyDataGost2012_256GetPrivateKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_256Id), NULL);
    return xmlSecGnuTLSAsymKeyDataGetPrivateKey(data);
}

static int
xmlSecGnuTLSKeyDataGost2012_256Initialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_256Id), -1);

    return(xmlSecGnuTLSAsymKeyDataInitialize(data));
}

static int
xmlSecGnuTLSKeyDataGost2012_256Duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecGnuTLSKeyDataGost2012_256Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecGnuTLSKeyDataGost2012_256Id), -1);

    return(xmlSecGnuTLSAsymKeyDataDuplicate(dst, src));
}

static void
xmlSecGnuTLSKeyDataGost2012_256Finalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_256Id));

    xmlSecGnuTLSAsymKeyDataFinalize(data);
}

static xmlSecKeyDataType
xmlSecGnuTLSKeyDataGost2012_256GetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_256Id), xmlSecKeyDataTypeUnknown);

    return xmlSecGnuTLSAsymKeyDataGetType(data);
}

static xmlSecSize
xmlSecGnuTLSKeyDataGost2012_256GetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_256Id), 0);

    return xmlSecGnuTLSAsymKeyDataGetSize(data);
}

static void
xmlSecGnuTLSKeyDataGost2012_256DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_256Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== GOST 2012 (256 bits) key: size = " XMLSEC_SIZE_FMT "\n",
            xmlSecGnuTLSKeyDataGost2012_256GetSize(data));
}

static void
xmlSecGnuTLSKeyDataGost2012_256DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_256Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<GOST2012_256KeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
            xmlSecGnuTLSKeyDataGost2012_256GetSize(data));
}

/**************************************************************************
 *
 * GOST R 34.10-2012 512 bit xml key representation processing
 *
 *************************************************************************/
static int              xmlSecGnuTLSKeyDataGost2012_512Initialize   (xmlSecKeyDataPtr data);
static int              xmlSecGnuTLSKeyDataGost2012_512Duplicate    (xmlSecKeyDataPtr dst,
                                                                     xmlSecKeyDataPtr src);
static void             xmlSecGnuTLSKeyDataGost2012_512Finalize     (xmlSecKeyDataPtr data);

static xmlSecKeyDataType xmlSecGnuTLSKeyDataGost2012_512GetType     (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecGnuTLSKeyDataGost2012_512GetSize      (xmlSecKeyDataPtr data);

static void             xmlSecGnuTLSKeyDataGost2012_512DebugDump    (xmlSecKeyDataPtr data,
                                                                     FILE* output);
static void             xmlSecGnuTLSKeyDataGost2012_512DebugXmlDump (xmlSecKeyDataPtr data,
                                                                     FILE* output);

static xmlSecKeyDataKlass xmlSecGnuTLSKeyDataGost2012_512Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecGnuTLSAsymKeyDataSize,

    /* data */
    xmlSecNameGostR3410_2012_512KeyValue,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefGostR3410_2012_512KeyValue,       /* const xmlChar* href; */
    xmlSecNodeGostR3410_2012_512KeyValue,       /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecGnuTLSKeyDataGost2012_512Initialize,  /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecGnuTLSKeyDataGost2012_512Duplicate,   /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecGnuTLSKeyDataGost2012_512Finalize,    /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecGnuTLSKeyDataGost2012_512GetType,     /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecGnuTLSKeyDataGost2012_512GetSize,     /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,                                       /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,                                       /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecGnuTLSKeyDataGost2012_512DebugDump,       /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecGnuTLSKeyDataGost2012_512DebugXmlDump,    /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSKeyDataGost2012_512GetKlass:
 *
 * The GnuTLS GOST 2012 (512 bits) key data klass.
 *
 * Returns: pointer to GnuTLS GOST 2012 (512 bits) key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataGost2012_512GetKlass(void) {
    return(&xmlSecGnuTLSKeyDataGost2012_512Klass);
}

/**
 * xmlSecGnuTLSKeyDataGost2012_512AdoptKey:
 * @data:               the pointer to GOST 2012 (512 bits) key data.
 * @pubkey:             the pointer to GnuTLS GOST 2012 (512 bits) key.
 * @privkey:            the pointer to GnuTLS GOST 2012 (512 bits) key.
 *
 * Sets the value of GOST 2012 (512 bits) key data. The @pubkey and @privkey will be owned by the @data on success.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataGost2012_512AdoptKey(xmlSecKeyDataPtr data, gnutls_pubkey_t pubkey, gnutls_privkey_t privkey) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_512Id), -1);
    return(xmlSecGnuTLSKeyDataGostAdoptKey(GNUTLS_PK_GOST_12_512, data, pubkey, privkey));
}

/**
 * xmlSecGnuTLSKeyDataGost2012_512GetPublicKey:
 * @data:               the pointer to GOST 2012 (512 bits) key data.
 *
 * Gets the GnuTLS GOST 2012 (512 bits) public key from GOST 2012 (512 bits) key data.
 *
 * Returns: pointer to GnuTLS public GOST 2012 (512 bits) key or NULL if an error occurs.
 */
gnutls_pubkey_t
xmlSecGnuTLSKeyDataGost2012_512GetPublicKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_512Id), NULL);
    return xmlSecGnuTLSAsymKeyDataGetPublicKey(data);
}

/**
 * xmlSecGnuTLSKeyDataGost2012_512GetPrivateKey:
 * @data:               the pointer to GOST 2012 (512 bits) key data.
 *
 * Gets the GnuTLS GOST 2012 (512 bits) private key from GOST 2012 (512 bits) key data.
 *
 * Returns: pointer to GnuTLS private GOST 2012 (512 bits) key or NULL if an error occurs.
 */
gnutls_privkey_t
xmlSecGnuTLSKeyDataGost2012_512GetPrivateKey(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_512Id), NULL);
    return xmlSecGnuTLSAsymKeyDataGetPrivateKey(data);
}

static int
xmlSecGnuTLSKeyDataGost2012_512Initialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_512Id), -1);

    return(xmlSecGnuTLSAsymKeyDataInitialize(data));
}

static int
xmlSecGnuTLSKeyDataGost2012_512Duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecGnuTLSKeyDataGost2012_512Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecGnuTLSKeyDataGost2012_512Id), -1);

    return(xmlSecGnuTLSAsymKeyDataDuplicate(dst, src));
}

static void
xmlSecGnuTLSKeyDataGost2012_512Finalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_512Id));

    xmlSecGnuTLSAsymKeyDataFinalize(data);
}

static xmlSecKeyDataType
xmlSecGnuTLSKeyDataGost2012_512GetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_512Id), xmlSecKeyDataTypeUnknown);

    return xmlSecGnuTLSAsymKeyDataGetType(data);
}

static xmlSecSize
xmlSecGnuTLSKeyDataGost2012_512GetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_512Id), 0);

    return xmlSecGnuTLSAsymKeyDataGetSize(data);
}

static void
xmlSecGnuTLSKeyDataGost2012_512DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_512Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== GOST 2012 (512 bits) key: size = " XMLSEC_SIZE_FMT "\n",
            xmlSecGnuTLSKeyDataGost2012_512GetSize(data));
}

static void
xmlSecGnuTLSKeyDataGost2012_512DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataGost2012_512Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<GOST2012_512KeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
            xmlSecGnuTLSKeyDataGost2012_512GetSize(data));
}

#endif /* XMLSEC_NO_GOST2012 */



/**************************************************************************
 *
 * Internal helper functions
 *
 **************************************************************************/
xmlSecKeyDataPtr
xmlSecGnuTLSAsymKeyDataCreate(gnutls_pubkey_t pubkey, gnutls_privkey_t privkey) {
    int pubkey_algo = GNUTLS_PK_UNKNOWN;
    int privkey_algo = GNUTLS_PK_UNKNOWN;
    int algo = GNUTLS_PK_UNKNOWN;
    xmlSecKeyDataPtr keyData;
    int ret;

    /* if we have 2 keys, figure out if algo is the same */
    if(pubkey != NULL) {
        pubkey_algo = gnutls_pubkey_get_pk_algorithm(pubkey, NULL);
    }
    if(privkey != NULL) {
        privkey_algo = gnutls_privkey_get_pk_algorithm(privkey, NULL);
    }
    if(pubkey_algo == GNUTLS_PK_UNKNOWN) {
        algo = privkey_algo;
    } else if(privkey_algo == GNUTLS_PK_UNKNOWN) {
        algo = pubkey_algo;
    } else if(pubkey_algo == privkey_algo) {
        algo = pubkey_algo;
    } else {
        xmlSecGnuTLSError("different algorithms for public and private key", GNUTLS_E_SUCCESS, NULL);
        return(NULL);
    }
    if(algo == GNUTLS_PK_UNKNOWN) {
        xmlSecGnuTLSError("cannot determine algorithm for public and private key", GNUTLS_E_SUCCESS, NULL);
        return(NULL);
    }

    switch(algo) {
#ifndef XMLSEC_NO_DSA
    case GNUTLS_PK_DSA:
        keyData = xmlSecKeyDataCreate(xmlSecGnuTLSKeyDataDsaId);
        if(keyData == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(DsaId)", NULL);
            return(NULL);
        }

        ret = xmlSecGnuTLSKeyDataDsaAdoptKey(keyData, pubkey, privkey);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataDsaAdoptKey", NULL);
            xmlSecKeyDataDestroy(keyData);
            return(NULL);
        }

        break;
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA
    case GNUTLS_PK_RSA:
        keyData = xmlSecKeyDataCreate(xmlSecGnuTLSKeyDataRsaId);
        if(keyData == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(RsaId)", NULL);
            return(NULL);
        }

        ret = xmlSecGnuTLSKeyDataRsaAdoptKey(keyData, pubkey, privkey);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataRsaAdoptKey", NULL);
            xmlSecKeyDataDestroy(keyData);
            return(NULL);
        }

        break;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_EC
    case GNUTLS_PK_ECDSA:
        keyData = xmlSecKeyDataCreate(xmlSecGnuTLSKeyDataEcId);
        if(keyData == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(EcdsaId)", NULL);
            return(NULL);
        }

        ret = xmlSecGnuTLSKeyDataEcAdoptKey(keyData, pubkey, privkey);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataEcAdoptKey", NULL);
            xmlSecKeyDataDestroy(keyData);
            return(NULL);
        }

        break;
#endif /* XMLSEC_NO_EC */

#ifndef XMLSEC_NO_GOST
    case GNUTLS_PK_GOST_01:
        keyData = xmlSecKeyDataCreate(xmlSecGnuTLSKeyDataGost2001Id);
        if(keyData == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(Gost2001Id)", NULL);
            return(NULL);
        }

        ret = xmlSecGnuTLSKeyDataGost2001AdoptKey(keyData, pubkey, privkey);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataGost2001AdoptKey", NULL);
            xmlSecKeyDataDestroy(keyData);
            return(NULL);
        }

        break;
#endif /* XMLSEC_NO_GOST */


#ifndef XMLSEC_NO_GOST2012
    case GNUTLS_PK_GOST_12_256:
        keyData = xmlSecKeyDataCreate(xmlSecGnuTLSKeyDataGost2012_256Id);
        if(keyData == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(2012_256Id)", NULL);
            return(NULL);
        }

        ret = xmlSecGnuTLSKeyDataGost2012_256AdoptKey(keyData, pubkey, privkey);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataGost2012_256AdoptKey", NULL);
            xmlSecKeyDataDestroy(keyData);
            return(NULL);
        }

        break;

   case GNUTLS_PK_GOST_12_512:
        keyData = xmlSecKeyDataCreate(xmlSecGnuTLSKeyDataGost2012_512Id);
        if(keyData == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(2012_512Id)", NULL);
            return(NULL);
        }

        ret = xmlSecGnuTLSKeyDataGost2012_512AdoptKey(keyData, pubkey, privkey);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataGost2012_512AdoptKey", NULL);
            xmlSecKeyDataDestroy(keyData);
            return(NULL);
        }

        break;
#endif /* XMLSEC_NO_GOST2012 */

        default:
            xmlSecInternalError2("Public / private key algorithm is not supported", NULL,
                "algo=%d", (int)algo);
            return(NULL);
    }

    /* done */
    return(keyData);
}
