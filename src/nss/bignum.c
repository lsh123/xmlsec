/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
/**
 * SECTION:bignum
 * @Short_description: Big numbers support functions implementation for NSS.
 * @Stability: Stable
 *
 */

#include "globals.h"

#include <stdlib.h>
#include <string.h>

#include <nss.h>
#include <secitem.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/buffer.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/bignum.h>

#include "../cast_helpers.h"

/**
 * xmlSecNssNodeGetBigNumValue:
 * @arena: the arena from which to allocate memory
 * @cur: the pointer to an XML node.
 * @a: a SECItem object to hold the BigNum value
 *
 * DEPRECATED. Converts the node content from CryptoBinary format
 * (http://www.w3.org/TR/xmldsig-core/#sec-CryptoBinary)
 * to a SECItem. If no SECItem object provided then a new
 * one is created (caller is responsible for freeing it).
 *
 * Returns: a pointer to SECItem produced from CryptoBinary string
 * or NULL if an error occurs.
 */
SECItem *
xmlSecNssNodeGetBigNumValue(PRArenaPool *arena, const xmlNodePtr cur,
                            SECItem *a) {
    xmlSecBuffer buf;
    int bufInitialized = 0;
    int ret;
    SECItem *rv = NULL;
    xmlSecSize size;
    unsigned int ulen;
    int len;

    xmlSecAssert2(arena != NULL, NULL);
    xmlSecAssert2(cur != NULL, NULL);

    ret = xmlSecBufferInitialize(&buf, 128);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        goto done;
    }
    bufInitialized = 1;

    ret = xmlSecBufferBase64NodeContentRead(&buf, cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase66NodeContentRead", NULL);
        goto done;
    }

    size = xmlSecBufferGetSize(&buf);
    XMLSEC_SAFE_CAST_SIZE_TO_INT(size, len, goto done, NULL);
    XMLSEC_SAFE_CAST_INT_TO_UINT(len, ulen, goto done, NULL);

    if (a == NULL) {
        rv = SECITEM_AllocItem(arena, NULL, ulen);
    } else {
        rv = a;
        xmlSecAssert2(rv->data == NULL, NULL);
        rv->len = ulen;
        rv->data = PORT_ArenaZAlloc(arena, ulen);
    }
    PORT_Memcpy(rv->data, xmlSecBufferGetData(&buf), ulen);

done:
    if(bufInitialized) {
        xmlSecBufferFinalize(&buf);
    }
    return(rv);
}

/**
 * xmlSecNssNodeSetBigNumValue:
 * @cur: the pointer to an XML node.
 * @a: a SECItem containing the BigNum value.
 * @addLineBreaks: if the flag is equal to 1 then
 *              linebreaks will be added before and after
 *              new buffer content.
 *
 * DEPRECATED. Converts SECItem to CryptoBinary string
 * (http://www.w3.org/TR/xmldsig-core/#sec-CryptoBinary)
 * and sets it as the content of the given node. If the
 * addLineBreaks is set then line breaks are added
 * before and after the CryptoBinary string.
 *
 * Returns: 0 on success or -1 otherwise.
 */
int
xmlSecNssNodeSetBigNumValue(xmlNodePtr cur, const SECItem *a, int addLineBreaks) {
    xmlSecBuffer buf;
    int ret;

    xmlSecAssert2(a != NULL, -1);
    xmlSecAssert2(cur != NULL, -1);

    ret = xmlSecBufferInitialize(&buf, a->len + 1);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize", NULL,
            "size=%u", (a->len + 1));
        return(-1);
    }

    PORT_Memcpy(xmlSecBufferGetData(&buf), a->data, a->len);

    ret = xmlSecBufferSetSize(&buf, a->len);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=%u", a->len);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    if(addLineBreaks) {
        xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
    } else {
        xmlNodeSetContent(cur, xmlSecStringEmpty);
    }

    ret = xmlSecBufferBase64NodeContentWrite(&buf, cur, xmlSecBase64GetDefaultLineSize());
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentWrite", NULL);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    if(addLineBreaks) {
        xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
    }

    xmlSecBufferFinalize(&buf);
    return(0);
}

