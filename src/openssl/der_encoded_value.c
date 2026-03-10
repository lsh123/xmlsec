/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * <dsig11:DEREncodedKeyValue /> processing for OpenSSL.
 *
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */
#include "globals.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>

#ifdef XMLSEC_OPENSSL_API_300
#include <openssl/provider.h>
#endif /* XMLSEC_OPENSSL_API_300 */

#include "../cast_helpers.h"
#include "private.h"


/**************************************************************************
 *
 * <dsig11:DEREncodedKeyValue /> processing
 *
 *************************************************************************/
static int                      xmlSecOpenSSLKeyDataDEREncodedKeyValueXmlRead(xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int                      xmlSecOpenSSLKeyDataDEREncodedKeyValueXmlWrite(xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);



static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataDEREncodedKeyValueKlass = {
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
    NULL,                                       /* DEPRECATED xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecOpenSSLKeyDataDEREncodedKeyValueXmlRead,     /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataDEREncodedKeyValueXmlWrite,    /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
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
 * xmlSecOpenSSLKeyDataDEREncodedKeyValueGetKlass:
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
xmlSecOpenSSLKeyDataDEREncodedKeyValueGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataDEREncodedKeyValueKlass);
}

static int
xmlSecOpenSSLKeyDataDEREncodedKeyValueXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecBuffer buffer;
    const xmlSecByte * data;
    xmlSecSize dataSize;
    long dataLen;
    EVP_PKEY * pKey = NULL;
    xmlSecKeyDataPtr keyData = NULL;
    xmlNodePtr cur;
    int res = -1;
    int ret;

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDEREncodedKeyValueId, -1);
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

    /* read pkey */
    XMLSEC_SAFE_CAST_SIZE_TO_LONG(dataSize, dataLen, goto done, xmlSecKeyDataKlassGetName(id));

#ifndef XMLSEC_OPENSSL_API_300
    pKey = d2i_PUBKEY(NULL, &data, dataLen);
    if(pKey == NULL) {
        xmlSecOpenSSLError2("d2i_PUBKEY", xmlSecKeyDataKlassGetName(id),
            "size=" XMLSEC_SIZE_FMT, dataSize);
        goto done;
    }
#else /* XMLSEC_OPENSSL_API_300 */
    pKey = d2i_PUBKEY_ex(NULL, &data, dataLen, xmlSecOpenSSLGetLibCtx(), NULL);
    if(pKey == NULL) {
        xmlSecOpenSSLError2("d2i_PUBKEY_ex", xmlSecKeyDataKlassGetName(id),
            "size=" XMLSEC_SIZE_FMT, dataSize);
        goto done;
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    /* add to key */
    keyData = xmlSecOpenSSLEvpKeyAdopt(pKey);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpKeyAdopt", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    pKey = NULL; /* owned by key data now */

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
    if(pKey != NULL) {
        EVP_PKEY_free(pKey);
    }
    xmlSecBufferFinalize(&buffer);
    return(res);
}

static int
xmlSecOpenSSLKeyDataDEREncodedKeyValueXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    EVP_PKEY * pKey;
    xmlSecByte * data = NULL;
    xmlSecSize dataSize = 0;
    xmlChar* content = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDEREncodedKeyValueId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->mode == xmlSecKeyInfoModeWrite, -1);

    /* get EVP_PKEY */
    pKey = xmlSecOpenSSLKeyGetEvp(key);
    if(pKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyGetEvp", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* encode pubkey */
    ret = i2d_PUBKEY(pKey, &data);
    if((ret <= 0) || (data == NULL)) {
        xmlSecOpenSSLError("i2d_PUBKEY", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    XMLSEC_SAFE_CAST_INT_TO_SIZE(ret, dataSize, goto done, xmlSecKeyDataKlassGetName(id));

    /* write to XML */
    content = xmlSecBase64Encode(data, dataSize, xmlSecBase64GetDefaultLineSize());
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
    if(data != NULL) {
        OPENSSL_free(data);
    }
    return(res);
}
