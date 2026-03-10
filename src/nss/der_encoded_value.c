/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * <dsig11:DEREncodedKeyValue /> processing for NSS.
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

#include <pk11pub.h>
#include <keyhi.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/pkikeys.h>

#include "../cast_helpers.h"


/**************************************************************************
 *
 * <dsig11:DEREncodedKeyValue /> processing
 *
 *************************************************************************/
static int                      xmlSecNssKeyDataDEREncodedKeyValueXmlRead(xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int                      xmlSecNssKeyDataDEREncodedKeyValueXmlWrite(xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);



static xmlSecKeyDataKlass xmlSecNssKeyDataDEREncodedKeyValueKlass = {
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
    xmlSecNssKeyDataDEREncodedKeyValueXmlRead,     /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecNssKeyDataDEREncodedKeyValueXmlWrite,    /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
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
 * xmlSecNssKeyDataDEREncodedKeyValueGetKlass:
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
xmlSecNssKeyDataDEREncodedKeyValueGetKlass(void) {
    return(&xmlSecNssKeyDataDEREncodedKeyValueKlass);
}

static int
xmlSecNssKeyDataDEREncodedKeyValueXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecBuffer buffer;
    xmlSecByte * data;
    xmlSecSize dataSize;
    SECItem secItem = { siBuffer, NULL, 0 };
    CERTSubjectPublicKeyInfo *spki = NULL;
    SECKEYPublicKey *pubkey = NULL;
    xmlSecKeyDataPtr keyData = NULL;
    xmlNodePtr cur;
    int res = -1;
    int ret;

    xmlSecAssert2(id == xmlSecNssKeyDataDEREncodedKeyValueId, -1);
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
    secItem.data = data;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(dataSize, secItem.len, goto done, xmlSecKeyDataKlassGetName(id));
    spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&secItem);
    if (spki == NULL) {
        xmlSecNssError("SECKEY_DecodeDERSubjectPublicKeyInfo", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    pubkey = SECKEY_ExtractPublicKey(spki);
    if (pubkey == NULL) {
        xmlSecNssError("SECKEY_ExtractPublicKey", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* add to key */
    keyData = xmlSecNssPKIAdoptKey(NULL, pubkey);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecNssPKIAdoptKey", xmlSecKeyDataKlassGetName(id));
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
        SECKEY_DestroyPublicKey(pubkey);
    }
    if(spki != NULL) {
        SECKEY_DestroySubjectPublicKeyInfo(spki);
    }
    xmlSecBufferFinalize(&buffer);
    return(res);
}

static int
xmlSecNssKeyDataDEREncodedKeyValueXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr keyData;
    SECKEYPublicKey* pubkey = NULL;
    SECItem* secItem = NULL;
    xmlChar* content = NULL;
    int res = -1;

    xmlSecAssert2(id == xmlSecNssKeyDataDEREncodedKeyValueId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->mode == xmlSecKeyInfoModeWrite, -1);

    /* get pubkey */
    keyData = xmlSecKeyGetValue(key);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecKeyGetValue", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    pubkey = xmlSecNssPKIKeyDataGetPubKey(keyData);
    if(pubkey == NULL) {
        xmlSecInternalError("xmlSecNssPKIKeyDataGetPubKey", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* encode it */
    secItem = SECKEY_EncodeDERSubjectPublicKeyInfo(pubkey);
    if((secItem == NULL) || (secItem->data == NULL) || (secItem->len <= 0)) {
        xmlSecNssError("SECKEY_EncodeDERSubjectPublicKeyInfo", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* write to XML */
    content = xmlSecBase64Encode(secItem->data, secItem->len, xmlSecBase64GetDefaultLineSize());
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
    if(pubkey != NULL) {
        SECKEY_DestroyPublicKey(pubkey);
    }
    if(secItem != NULL) {
        SECITEM_FreeItem(secItem, PR_TRUE);
    }
    return(res);
}
