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
 * SECTION:bn
 * @Short_description: Big numbers (BIGNUM) support functions implementation for OpenSSL.
 * @Stability: Stable
 *
 */

#include "globals.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/buffer.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/bn.h>

/**
 * xmlSecOpenSSLNodeGetBNValue:
 * @cur: the pointer to an XML node.
 * @a: the BIGNUM buffer.
 *
 * Converts the node content from CryptoBinary format
 * (http://www.w3.org/TR/xmldsig-core/#sec-CryptoBinary)
 * to a BIGNUM. If no BIGNUM buffer provided then a new
 * BIGNUM is created (caller is responsible for freeing it).
 *
 * Returns: a pointer to BIGNUM produced from CryptoBinary string
 * or NULL if an error occurs.
 */
BIGNUM*
xmlSecOpenSSLNodeGetBNValue(const xmlNodePtr cur, BIGNUM **a) {
    xmlSecBuffer buf;
    int ret;

    xmlSecAssert2(cur != NULL, NULL);

    ret = xmlSecBufferInitialize(&buf, 128);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        return(NULL);
    }

    ret = xmlSecBufferBase64NodeContentRead(&buf, cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentRead", NULL);
        xmlSecBufferFinalize(&buf);
        return(NULL);
    }

    (*a) = BN_bin2bn(xmlSecBufferGetData(&buf), xmlSecBufferGetSize(&buf), (*a));
    if( (*a) == NULL) {
        xmlSecOpenSSLError2("BN_bin2bn", NULL,
                            "size=%lu", (unsigned long)(xmlSecBufferGetSize(&buf)));
        xmlSecBufferFinalize(&buf);
        return(NULL);
    }
    xmlSecBufferFinalize(&buf);
    return(*a);
}

/**
 * xmlSecOpenSSLNodeSetBNValue:
 * @cur: the pointer to an XML node.
 * @a: the BIGNUM.
 * @addLineBreaks: if the flag is equal to 1 then
 *              linebreaks will be added before and after
 *              new buffer content.
 *
 * Converts BIGNUM to CryptoBinary string
 * (http://www.w3.org/TR/xmldsig-core/#sec-CryptoBinary)
 * and sets it as the content of the given node. If the
 * addLineBreaks is set then line breaks are added
 * before and after the CryptoBinary string.
 *
 * Returns: 0 on success or -1 otherwise.
 */
int
xmlSecOpenSSLNodeSetBNValue(xmlNodePtr cur, const BIGNUM *a, int addLineBreaks) {
    xmlSecBuffer buf;
    xmlSecSize size;
    int ret;

    xmlSecAssert2(a != NULL, -1);
    xmlSecAssert2(cur != NULL, -1);

    ret = xmlSecBufferInitialize(&buf, BN_num_bytes(a) + 1);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize", NULL,
                             "size=%d", BN_num_bytes(a) + 1);
        return(-1);
    }

    ret = BN_bn2bin(a, xmlSecBufferGetData(&buf));
    if(ret < 0) {
        xmlSecOpenSSLError("BN_bn2bin", NULL);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }
    size = ret;

    ret = xmlSecBufferSetSize(&buf, size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
                             "size=%d", size);
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

