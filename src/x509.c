/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/parser.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/x509.h>
#include <xmlsec/errors.h>

/**
 * xmlSecX509DataGetNodeContent:
 * @node:               the pointer to <dsig:X509Data/> node.
 * @deleteChildren:     the flag that indicates whether to remove node children after reading.
 * @keyInfoCtx:         the pointer to <dsig:KeyInfo/> node processing context.
 *
 * Reads the contents of <dsig:X509Data/> node and returns it as
 * a bits mask.
 *
 * Returns: the bit mask representing the <dsig:X509Data/> node content
 * or a negative value if an error occurs.
 */
int
xmlSecX509DataGetNodeContent (xmlNodePtr node, int deleteChildren,
                            xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlNodePtr cur, next;
    int deleteCurNode;
    int content = 0;

    xmlSecAssert2(node != NULL, 0);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* determine the current node content */
    cur = xmlSecGetNextElementNode(node->children);
    while(cur != NULL) {
        deleteCurNode = 0;
        if(xmlSecCheckNodeName(cur, xmlSecNodeX509Certificate, xmlSecDSigNs)) {
            if(xmlSecIsEmptyNode(cur) == 1) {
                content |= XMLSEC_X509DATA_CERTIFICATE_NODE;
                deleteCurNode = 1;
            }
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509SubjectName, xmlSecDSigNs)) {
            if(xmlSecIsEmptyNode(cur) == 1) {
                content |= XMLSEC_X509DATA_SUBJECTNAME_NODE;
                deleteCurNode = 1;
            }
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509IssuerSerial, xmlSecDSigNs)) {
            if(xmlSecIsEmptyNode(cur) == 1) {
                content |= XMLSEC_X509DATA_ISSUERSERIAL_NODE;
                deleteCurNode = 1;
            }
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509SKI, xmlSecDSigNs)) {
            if(xmlSecIsEmptyNode(cur) == 1) {
                content |= XMLSEC_X509DATA_SKI_NODE;
                deleteCurNode = 1;
            }
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509CRL, xmlSecDSigNs)) {
            if(xmlSecIsEmptyNode(cur) == 1) {
                content |= XMLSEC_X509DATA_CRL_NODE;
                deleteCurNode = 1;
            }
        } else {
            /* todo: fail on unknown child node? */
        }
        next = xmlSecGetNextElementNode(cur->next);
        if((deleteCurNode != 0) && (deleteChildren != 0)) {
            /* remove "template" nodes */
            xmlUnlinkNode(cur);
            xmlFreeNode(cur);
        }
        cur = next;
    }

    return (content);
}

#endif /* XMLSEC_NO_X509 */

