/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Helper functions for X509 certificate processing.
 */
#include "globals.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include "x509_helpers.h"


#ifndef XMLSEC_NO_X509


#define XMLSEC_X509_NAME_SIZE                       256
#define XMLSEC_X509_VALUE_SIZE                      1024


#define XMLSEC_X509_NAME_READ_STATE_NORMAL          0
#define XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH1    1
#define XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH2    2
#define XMLSEC_X509_NAME_READ_STATE_DELIMETER       3

/******************************************************************************
 *
 * Helper functions to read/write &lt;dsig:X509Data/&gt;
 *
 *
 * The X509Data Element (http://www.w3.org/TR/xmldsig-core/#sec-X509Data)
 *
 * An X509Data element within KeyInfo contains one or more identifiers of keys
 * or X509 certificates (or certificates' identifiers or a revocation list).
 * The content of X509Data is:
 *
 *  1. At least one element, from the following set of element types; any of these may appear together or more than once iff (if and only if) each instance describes or is related to the same certificate:
 *  2.
 *    * The X509IssuerSerial element, which contains an X.509 issuer
 *      distinguished name/serial number pair that SHOULD be compliant
 *      with RFC2253 [LDAP-DN],
 *    * The X509SubjectName element, which contains an X.509 subject
 *      distinguished name that SHOULD be compliant with RFC2253 [LDAP-DN],
 *    * The X509SKI element, which contains the base64 encoded plain (i.e.
 *      non-DER-encoded) value of a X509 V.3 SubjectKeyIdentifier extension.
 *    * The X509Certificate element, which contains a base64-encoded [X509v3]
 *      certificate, and
 *    * Elements from an external namespace which accompanies/complements any
 *      of the elements above.
 *    * The X509CRL element, which contains a base64-encoded certificate
 *      revocation list (CRL) [X509v3].
 *
 * Any X509IssuerSerial, X509SKI, and X509SubjectName elements that appear
 * MUST refer to the certificate or certificates containing the validation key.
 * All such elements that refer to a particular individual certificate MUST be
 * grouped inside a single X509Data element and if the certificate to which
 * they refer appears, it MUST also be in that X509Data element.
 *
 * Any X509IssuerSerial, X509SKI, and X509SubjectName elements that relate to
 * the same key but different certificates MUST be grouped within a single
 * KeyInfo but MAY occur in multiple X509Data elements.
 *
 * All certificates appearing in an X509Data element MUST relate to the
 * validation key by either containing it or being part of a certification
 * chain that terminates in a certificate containing the validation key.
 *
 * No ordering is implied by the above constraints.
 *
 * Note, there is no direct provision for a PKCS#7 encoded "bag" of
 * certificates or CRLs. However, a set of certificates and CRLs can occur
 * within an X509Data element and multiple X509Data elements can occur in a
 * KeyInfo. Whenever multiple certificates occur in an X509Data element, at
 * least one such certificate must contain the public key which verifies the
 * signature.
 *
 * <programlisting><![CDATA[
 *  Schema Definition:
 *
 *  <element name="X509Data" type="ds:X509DataType"/>
 *  <complexType name="X509DataType">
 *    <sequence maxOccurs="unbounded">
 *      <choice>
 *        <element name="X509IssuerSerial" type="ds:X509IssuerSerialType"/>
 *        <element name="X509SKI" type="base64Binary"/>
 *        <element name="X509SubjectName" type="string"/>
 *        <element name="X509Certificate" type="base64Binary"/>
 *        <element name="X509CRL" type="base64Binary"/>
 *        <any namespace="##other" processContents="lax"/>
 *      </choice>
 *    </sequence>
 *  </complexType>
 *  <complexType name="X509IssuerSerialType">
 *    <sequence>
 *       <element name="X509IssuerName" type="string"/>
 *       <element name="X509SerialNumber" type="integer"/>
 *     </sequence>
 *  </complexType>
 *
 *  DTD:
 *
 *    <!ELEMENT X509Data ((X509IssuerSerial | X509SKI | X509SubjectName |
 *                          X509Certificate | X509CRL)+ %X509.ANY;)>
 *    <!ELEMENT X509IssuerSerial (X509IssuerName, X509SerialNumber) >
 *    <!ELEMENT X509IssuerName (#PCDATA) >
 *    <!ELEMENT X509SubjectName (#PCDATA) >
 *    <!ELEMENT X509SerialNumber (#PCDATA) >
 *    <!ELEMENT X509SKI (#PCDATA) >
 *    <!ELEMENT X509Certificate (#PCDATA) >
 *    <!ELEMENT X509CRL (#PCDATA) >
 * ]]></programlisting>
 *
  *****************************************************************************/
#define XMLSEC_KEY_DATA_X509_INIT_BUF_SIZE     512

static int                      xmlSecKeyX509DataValueInitialize            (xmlSecKeyX509DataValuePtr x509Value);
static void                     xmlSecKeyX509DataValueFinalize              (xmlSecKeyX509DataValuePtr x509Value);
static void                     xmlSecKeyX509DataValueReset                 (xmlSecKeyX509DataValuePtr x509Value,
                                                                             int writeMode);
static int                      xmlSecKeyX509DataValueXmlRead               (xmlSecKeyX509DataValuePtr x509Value,
                                                                             xmlNodePtr node,
                                                                             xmlSecKeyInfoCtxPtr keyInfoCtx);
static int                      xmlSecKeyX509DataValueXmlWrite              (xmlSecKeyX509DataValuePtr x509Value,
                                                                             xmlNodePtr node,
                                                                             int base64LineSize,
                                                                             int addLineBreaks);

/**
 * @brief X509 Key data method for reading XML node.
 * @param key the resulting key
 * @param data the X509 key data.
 * @param node the pointer to data's value XML node.
 * @param keyInfoCtx the &lt;dsig:KeyInfo/&gt; node processing context.
 * @param readFunc the pointer to the function that converts
 *                      xmlSecKeyX509DataValue to xmlSecKeyData.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataX509XmlRead(xmlSecKeyPtr key, xmlSecKeyDataPtr data, xmlNodePtr node,
    xmlSecKeyInfoCtxPtr keyInfoCtx, xmlSecKeyDataX509Read readFunc
) {
    xmlSecKeyX509DataValue x509Value;
    int x509ValueInitialized = 0;
    xmlNodePtr cur;
    int keyFound = 0;
    int res = -1;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    ret = xmlSecKeyX509DataValueInitialize(&x509Value);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyX509DataValueInitialize", NULL);
        goto done;
    }
    x509ValueInitialized = 1;

    for(cur = xmlSecGetNextElementNode(node->children); cur != NULL; cur = xmlSecGetNextElementNode(cur->next)) {
        ret = xmlSecKeyX509DataValueXmlRead(&x509Value, cur, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeyX509DataValueXmlRead", NULL);
            goto done;
        }

        /* first try to lookup key in keys manager using x509 data */
        if(keyFound == 0) {
            xmlSecKeyPtr tmpKey;

            tmpKey = xmlSecKeysMngrFindKeyFromX509Data(keyInfoCtx->keysMngr, &x509Value, keyInfoCtx);
            if(tmpKey != NULL) {
                ret = xmlSecKeySwap(key, tmpKey);
                if(ret < 0) {
                    xmlSecInternalError("xmlSecKeysMngrFindKeyFromX509Data", NULL);
                    xmlSecKeyDestroy(tmpKey);
                    goto done;
                }
                xmlSecKeyDestroy(tmpKey);

                /* key was found but we want to keep reading X509Data node to ensure it is valid */
                keyFound = 1;
            }
        }

        /* otherwise, see if we can get it from certs, etc */
        if((keyFound == 0) && (readFunc != NULL)) {
            /* xmlSecKeyDataX509Read: 0 on success and a negative value otherwise */
            ret = readFunc(data, &x509Value, keyInfoCtx->keysMngr, keyInfoCtx->flags);
            if(ret < 0) {
                xmlSecInternalError("xmlSecKeyDataX509Read", NULL);
                goto done;
            }
        }

        /* cleanup for the next node */
        xmlSecKeyX509DataValueReset(&x509Value, 0);
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(x509ValueInitialized != 0) {
        xmlSecKeyX509DataValueFinalize(&x509Value);
    }

    return(res);
}


static int
xmlSecX509DataGetNodeContent(xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx, xmlChar** digestAlgorithm) {
    xmlNodePtr cur;
    int content = 0;

    xmlSecAssert2(node != NULL, 0);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(digestAlgorithm != NULL, -1);
    xmlSecAssert2((*digestAlgorithm) == NULL, -1);

    /* determine the current node content */
    cur = xmlSecGetNextElementNode(node->children);
    while(cur != NULL) {
        if(xmlSecCheckNodeName(cur, xmlSecNodeX509Certificate, xmlSecDSigNs)) {
            if(xmlSecIsEmptyNode(cur) == 1) {
                content |= XMLSEC_X509DATA_CERTIFICATE_NODE;
            } else {
                /* ensure return value isn't 0 if there are non-empty elements */
                content |= (XMLSEC_X509DATA_CERTIFICATE_NODE << XMLSEC_X509DATA_SHIFT_IF_NOT_EMPTY);
            }
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509SubjectName, xmlSecDSigNs)) {
            if(xmlSecIsEmptyNode(cur) == 1) {
                content |= XMLSEC_X509DATA_SUBJECTNAME_NODE;
            } else {
                content |= (XMLSEC_X509DATA_SUBJECTNAME_NODE << XMLSEC_X509DATA_SHIFT_IF_NOT_EMPTY);
            }
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509IssuerSerial, xmlSecDSigNs)) {
            if(xmlSecIsEmptyNode(cur) == 1) {
                content |= XMLSEC_X509DATA_ISSUERSERIAL_NODE;
            } else {
                content |= (XMLSEC_X509DATA_ISSUERSERIAL_NODE << XMLSEC_X509DATA_SHIFT_IF_NOT_EMPTY);
            }
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509SKI, xmlSecDSigNs)) {
            if(xmlSecIsEmptyNode(cur) == 1) {
                content |= XMLSEC_X509DATA_SKI_NODE;
            } else {
                content |= (XMLSEC_X509DATA_SKI_NODE << XMLSEC_X509DATA_SHIFT_IF_NOT_EMPTY);
            }
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509Digest, xmlSecDSig11Ns)) {
            if(xmlSecIsEmptyNode(cur) == 1) {
                content |= XMLSEC_X509DATA_DIGEST_NODE;
            } else {
                content |= (XMLSEC_X509DATA_DIGEST_NODE << XMLSEC_X509DATA_SHIFT_IF_NOT_EMPTY);
            }
            /* only read the first digestAlgorithm */
            if((*digestAlgorithm) == NULL) {
                (*digestAlgorithm) = xmlGetProp(cur, xmlSecAttrAlgorithm);
                if((*digestAlgorithm) == NULL) {
                    xmlSecInvalidNodeAttributeError(cur, xmlSecAttrAlgorithm, NULL, "empty");
                    return(-1);
                }
            }
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509CRL, xmlSecDSigNs)) {
            if(xmlSecIsEmptyNode(cur) == 1) {
                content |= XMLSEC_X509DATA_CRL_NODE;
            } else {
                content |= (XMLSEC_X509DATA_CRL_NODE << 16);
            }
        } else {
            /* todo: fail on unknown child node? */
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    return (content);
}

/**
 * @brief DSA Key data  method for writing XML node.
 * @param data the x509 key data.
 * @param node the pointer to data's value XML node.
 * @param keyInfoCtx the &lt;dsig:KeyInfo/&gt; node processing context.
 * @param base64LineSize the base64 max line size.
 * @param addLineBreaks the flag indicating if we need to add line breaks around base64 output.
 * @param writeFunc the pointer to the function that converts
 *                      xmlSecKeyData to  xmlSecKeyValueDsa.
 * @param writeFuncContext the context passed to @p writeFunc.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataX509XmlWrite(xmlSecKeyDataPtr data, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx,
                          int base64LineSize, int addLineBreaks,
                          xmlSecKeyDataX509Write writeFunc, void* writeFuncContext) {
    xmlSecKeyX509DataValue x509Value;
    int x509ValueInitialized = 0;
    int content;
    int ret;
    int res = -1;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(base64LineSize > 0, -1);
    xmlSecAssert2(writeFunc != NULL, -1);

    if(((xmlSecKeyDataTypePublic) & keyInfoCtx->keyReq.keyType) == 0) {
        /* we can only write public key */
        return(0);
    }

    ret = xmlSecKeyX509DataValueInitialize(&x509Value);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyX509DataValueInitialize",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    x509ValueInitialized = 1;


    content = xmlSecX509DataGetNodeContent(node, keyInfoCtx, &(x509Value.digestAlgorithm));
    if (content < 0) {
        xmlSecInternalError2("xmlSecX509DataGetNodeContent",
            xmlSecKeyDataGetName(data), "content=%d", content);
        goto done;
    } else if(content == 0) {
        /* by default we are writing certificates and crls */
        content = XMLSEC_X509DATA_DEFAULT;
    }

    while(1) {
        /* xmlSecKeyDataX509Write: returns 1 on success, 0 if no more certs/crls are available,
         * or a negative value if an error occurs.
         */
        ret = writeFunc(data, &x509Value, content, writeFuncContext);
        if(ret < 0) {
            xmlSecInternalError("writeFunc", xmlSecKeyDataGetName(data));
            goto done;
        } else if (ret == 0) {
            break;
        }

        ret = xmlSecKeyX509DataValueXmlWrite(&x509Value, node, base64LineSize, addLineBreaks);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeyX509DataValueXmlWrite", xmlSecKeyDataGetName(data));
            goto done;
        }

         /* cleanup for the next obj */
        xmlSecKeyX509DataValueReset(&x509Value, 1);
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(x509ValueInitialized != 0) {
        xmlSecKeyX509DataValueFinalize(&x509Value);
    }

    return(res);
}

static int
xmlSecKeyX509DataValueInitialize(xmlSecKeyX509DataValuePtr x509Value) {
    int ret;

    xmlSecAssert2(x509Value != NULL, -1);
    memset(x509Value, 0, sizeof(xmlSecKeyX509DataValue));

    ret = xmlSecBufferInitialize(&(x509Value->cert), XMLSEC_KEY_DATA_X509_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(cert)", NULL);
        xmlSecKeyX509DataValueFinalize(x509Value);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(x509Value->crl), XMLSEC_KEY_DATA_X509_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(crl)", NULL);
        xmlSecKeyX509DataValueFinalize(x509Value);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(x509Value->ski), XMLSEC_KEY_DATA_X509_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(ski)", NULL);
        xmlSecKeyX509DataValueFinalize(x509Value);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(x509Value->digest), XMLSEC_KEY_DATA_X509_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(digest)", NULL);
        xmlSecKeyX509DataValueFinalize(x509Value);
        return(-1);
    }
    return(0);
}

static void
xmlSecKeyX509DataValueFinalize(xmlSecKeyX509DataValuePtr x509Value) {
    xmlSecAssert(x509Value != NULL);

    xmlSecBufferFinalize(&(x509Value->cert));
    xmlSecBufferFinalize(&(x509Value->crl));
    xmlSecBufferFinalize(&(x509Value->ski));

    if(x509Value->subject != NULL) {
        xmlFree(x509Value->subject);
    }

    if(x509Value->issuerName != NULL) {
        xmlFree(x509Value->issuerName);
    }
    if(x509Value->issuerSerial != NULL) {
        xmlFree(x509Value->issuerSerial);
    }

    if(x509Value->digestAlgorithm != NULL) {
        xmlFree(x509Value->digestAlgorithm);
    }
    xmlSecBufferFinalize(&(x509Value->digest));

    memset(x509Value, 0, sizeof(xmlSecKeyX509DataValue));
}

static void
xmlSecKeyX509DataValueReset(xmlSecKeyX509DataValuePtr x509Value, int writeMode) {
    xmlSecAssert(x509Value != NULL);

    xmlSecBufferEmpty(&(x509Value->cert));
    xmlSecBufferEmpty(&(x509Value->crl));
    xmlSecBufferEmpty(&(x509Value->ski));

    if(x509Value->subject != NULL) {
        xmlFree(x509Value->subject);
        x509Value->subject = NULL;
    }

    if(x509Value->issuerName != NULL) {
        xmlFree(x509Value->issuerName);
        x509Value->issuerName = NULL;
    }
    if(x509Value->issuerSerial != NULL) {
        xmlFree(x509Value->issuerSerial);
        x509Value->issuerSerial = NULL;
    }

    /* we keep digest algorithm as-is for the next certificate if we are writing it out */
    if((writeMode == 0) && (x509Value->digestAlgorithm != NULL)) {
        xmlFree(x509Value->digestAlgorithm);
        x509Value->digestAlgorithm = NULL;
    }
    xmlSecBufferEmpty(&(x509Value->digest));

}

static int
xmlSecKeyX509DataValueXmlReadBase64Blob(xmlSecBufferPtr buf, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlChar *content;
    xmlSecSize decodedSize;
    int ret;
    int res = -1;

    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    content = xmlSecGetNodeContentAndTrim(node);
    if((content == NULL) || (xmlSecIsEmptyString(content) == 1)) {
        if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_STOP_ON_EMPTY_NODE) != 0) {
            xmlSecInvalidNodeContentError(node, NULL, "empty");
            goto done;
        }

        /* success */
        res = 0;
        goto done;
    }

    /* usual trick with base64 decoding "in-place" */
    decodedSize = 0;
    ret = xmlSecBase64DecodeInPlace(content, &decodedSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBase64DecodeInPlace", NULL,
            "node=%s", xmlSecErrorsSafeString(xmlSecNodeGetName(node)));
        goto done;
    }

    ret = xmlSecBufferSetData(buf, (xmlSecByte*)content, decodedSize);
    if(ret < 0) {
        xmlSecInternalError3("xmlSecBufferSetData", NULL,
            "node=%s; size=" XMLSEC_SIZE_FMT,
            xmlSecErrorsSafeString(xmlSecNodeGetName(node)),
            decodedSize);
        goto done;
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(content != NULL) {
        xmlFree(content);
    }
    return(res);
}

static int
xmlSecKeyX509DataValueXmlReadString(xmlChar **str, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlChar *content;
    int res = -1;

    xmlSecAssert2(str != NULL, -1);
    xmlSecAssert2((*str) == NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    content = xmlSecGetNodeContentAndTrim(node);
    if((content == NULL) || (xmlStrlen(content) <= 0)) {
        if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_STOP_ON_EMPTY_NODE) != 0) {
            xmlSecInvalidNodeContentError(node, NULL, "empty");
            goto done;
        }

        /* success */
        res = 0;
        goto done;
    }

    /* success */
    (*str) = content;
    content = NULL;
    res = 0;

done:
    /* cleanup */
    if(content != NULL) {
        xmlFree(content);
    }
    return(res);
}

static int
xmlSecKeyX509DataValueXmlReadIssuerSerial(xmlSecKeyX509DataValuePtr x509Value, xmlNodePtr node,
    xmlSecKeyInfoCtxPtr keyInfoCtx
) {
    xmlNodePtr cur;

    xmlSecAssert2(x509Value != NULL, -1);
    xmlSecAssert2(x509Value->issuerName == NULL, -1);
    xmlSecAssert2(x509Value->issuerSerial == NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    cur = xmlSecGetNextElementNode(node->children);
    if(cur == NULL) {
        if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_STOP_ON_EMPTY_NODE) != 0) {
            xmlSecNodeNotFoundError("xmlSecGetNextElementNode", node, NULL, NULL);
            return(-1);
        }
        return(0);
    }

    /* the first is required node X509IssuerName */
    if(!xmlSecCheckNodeName(cur, xmlSecNodeX509IssuerName, xmlSecDSigNs)) {
        xmlSecInvalidNodeError(cur, xmlSecNodeX509IssuerName, NULL);
        return(-1);
    }
    x509Value->issuerName = xmlSecGetNodeContentAndTrim(cur);
    if((x509Value->issuerName == NULL) || (xmlSecIsEmptyString(x509Value->issuerName) == 1)) {
        xmlSecInvalidNodeContentError(cur, NULL, "empty");
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is required node X509SerialNumber */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, xmlSecNodeX509SerialNumber, xmlSecDSigNs)) {
        xmlSecInvalidNodeError(cur, xmlSecNodeX509SerialNumber, NULL);
        return(-1);
    }
    x509Value->issuerSerial  = xmlSecGetNodeContentAndTrim(cur);
    if((x509Value->issuerSerial == NULL) || (xmlSecIsEmptyString(x509Value->issuerSerial) == 1)) {
        xmlSecInvalidNodeContentError(cur, NULL, "empty");
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* nothing else is expected */
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecKeyX509DataValueXmlRead(xmlSecKeyX509DataValuePtr x509Value, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    int ret;

    xmlSecAssert2(x509Value != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(xmlSecCheckNodeName(node, xmlSecNodeX509Certificate, xmlSecDSigNs)) {
        ret = xmlSecKeyX509DataValueXmlReadBase64Blob(&(x509Value->cert), node, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeyX509DataValueXmlReadBase64Blob(cert)", NULL);
            return(-1);
        }
    } else if(xmlSecCheckNodeName(node, xmlSecNodeX509CRL, xmlSecDSigNs)) {
        ret = xmlSecKeyX509DataValueXmlReadBase64Blob(&(x509Value->crl), node, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeyX509DataValueXmlReadBase64Blob(crl)", NULL);
            return(-1);
        }
    } else if(xmlSecCheckNodeName(node, xmlSecNodeX509SKI, xmlSecDSigNs)) {
        ret = xmlSecKeyX509DataValueXmlReadBase64Blob(&(x509Value->ski), node, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeyX509DataValueXmlReadBase64Blob(ski)", NULL);
            return(-1);
        }
    } else if(xmlSecCheckNodeName(node, xmlSecNodeX509SubjectName, xmlSecDSigNs)) {
        ret = xmlSecKeyX509DataValueXmlReadString(&(x509Value->subject), node, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeyX509DataValueXmlReadString(subject)", NULL);
            return(-1);
        }
    } else if(xmlSecCheckNodeName(node, xmlSecNodeX509IssuerSerial, xmlSecDSigNs)) {
        ret = xmlSecKeyX509DataValueXmlReadIssuerSerial(x509Value, node, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeyX509DataValueXmlReadIssuerSerial", NULL);
            return(-1);
        }
    } else if(xmlSecCheckNodeName(node, xmlSecNodeX509Digest, xmlSecDSig11Ns)) {
        xmlSecAssert2(x509Value->digestAlgorithm == NULL, -1);

        /*  The digest algorithm URI is identified with a required Algorithm attribute */
        x509Value->digestAlgorithm = xmlGetProp(node, xmlSecAttrAlgorithm);
        if(x509Value->digestAlgorithm == NULL) {
            xmlSecInvalidNodeAttributeError(node, xmlSecAttrAlgorithm, NULL, "empty");
            return(-1);
        }

        /* The&lt;dsig11:X509Digest/&gt; element contains a base64-encoded digest of a certificate. */
        ret = xmlSecKeyX509DataValueXmlReadBase64Blob(&(x509Value->digest), node, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeyX509DataValueXmlReadBase64Blob(digest)", NULL);
            return(-1);
        }

    } else if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CHILD) != 0) {
        /* laxi schema validation: ignore unknown nodes */
        xmlSecUnexpectedNodeError(node, NULL);
        return(-1);
    }

    /* done */
    return(0);
}

static xmlNodePtr
xmlSecKeyX509DataValueXmlWriteBase64Blob(xmlSecBufferPtr buf, xmlNodePtr node,
                                    const xmlChar* nodeName, const xmlChar* nodeNs,
                                    int base64LineSize, int addLineBreaks) {
    xmlNodePtr child = NULL;
    xmlChar *content;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(node != NULL, NULL);
    xmlSecAssert2(nodeName != NULL, NULL);

    content = xmlSecBase64Encode(xmlSecBufferGetData(buf), xmlSecBufferGetSize(buf),
        base64LineSize);
    if(content == NULL) {
        xmlSecInternalError("xmlSecBase64Encode", NULL);
        goto done;
    }

    child = xmlSecEnsureEmptyChild(node, nodeName, nodeNs);
    if(child == NULL) {
        xmlSecInternalError2("xmlSecEnsureEmptyChild()", NULL,
            "nodeName=%s", xmlSecErrorsSafeString(nodeName));
        goto done;
    }

    if(addLineBreaks) {
        xmlNodeAddContent(child, xmlSecGetDefaultLineFeed());
    }

    xmlNodeSetContent(child, content);

    if(addLineBreaks) {
        xmlNodeAddContent(child, xmlSecGetDefaultLineFeed());
    }

    /* success */

done:
    /* cleanup */
    if(content != NULL) {
        xmlFree(content);
    }
    return(child);
}


static int
xmlSecKeyX509DataValueXmlWriteString(const xmlChar* content, xmlNodePtr node,
                                 const xmlChar* nodeName, const xmlChar* nodeNs) {
    xmlNodePtr cur;

    xmlSecAssert2(content != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(nodeName != NULL, -1);

    cur = xmlSecEnsureEmptyChild(node, nodeName, nodeNs);
    if(cur == NULL) {
        xmlSecInternalError2("xmlSecEnsureEmptyChild()", NULL,
            "nodeName=%s", xmlSecErrorsSafeString(nodeName));
        return(-1);
    }

    xmlNodeSetContent(cur, content);

    /* success */
    return(0);
}

static int
xmlSecKeyX509DataValueXmlWrite(xmlSecKeyX509DataValuePtr x509Value, xmlNodePtr node,
                           int base64LineSize, int addLineBreaks) {
    xmlSecAssert2(x509Value != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    if(!xmlSecBufferIsEmpty(&(x509Value->cert))) {
        xmlNodePtr child;

        child = xmlSecKeyX509DataValueXmlWriteBase64Blob(&(x509Value->cert), node,
            xmlSecNodeX509Certificate, xmlSecDSigNs,
            base64LineSize, addLineBreaks);
        if(child == NULL) {
            xmlSecInternalError("xmlSecKeyX509DataValueXmlWriteBase64Blob(cert)", NULL);
            return(-1);
        }
    }
    if(!xmlSecBufferIsEmpty(&(x509Value->crl))) {
        xmlNodePtr child;

        child = xmlSecKeyX509DataValueXmlWriteBase64Blob(&(x509Value->crl), node,
            xmlSecNodeX509CRL, xmlSecDSigNs,
            base64LineSize, addLineBreaks);
        if(child == NULL) {
            xmlSecInternalError("xmlSecKeyX509DataValueXmlWriteBase64Blob(cert)", NULL);
            return(-1);
        }
    }
    if(!xmlSecBufferIsEmpty(&(x509Value->ski))) {
        xmlNodePtr child;

        child = xmlSecKeyX509DataValueXmlWriteBase64Blob(&(x509Value->ski), node,
            xmlSecNodeX509SKI, xmlSecDSigNs,
            base64LineSize, addLineBreaks);
        if(child == NULL) {
            xmlSecInternalError("xmlSecKeyX509DataValueXmlWriteBase64Blob(ski)", NULL);
            return(-1);
        }
    }
    if(x509Value->subject != NULL) {
        int ret;

        ret = xmlSecKeyX509DataValueXmlWriteString(x509Value->subject, node,
            xmlSecNodeX509SubjectName, xmlSecDSigNs);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecKeyX509DataValueXmlWriteString", NULL,
                "subject=%s", xmlSecErrorsSafeString(x509Value->subject));
            return(-1);
        }
    }
    if((x509Value->issuerName != NULL) && (x509Value->issuerSerial != NULL)) {
        xmlNodePtr issuerSerial;
        int ret;

        issuerSerial = xmlSecEnsureEmptyChild(node, xmlSecNodeX509IssuerSerial, xmlSecDSigNs);
        if(issuerSerial == NULL) {
            xmlSecInternalError("xmlSecEnsureEmptyChild(xmlSecNodeX509IssuerSerial)", NULL);
            return(-1);
        }
        ret = xmlSecKeyX509DataValueXmlWriteString(x509Value->issuerName, issuerSerial,
            xmlSecNodeX509IssuerName, xmlSecDSigNs);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecKeyX509DataValueXmlWriteString", NULL,
                "issuerName=%s", xmlSecErrorsSafeString(x509Value->issuerName));
            return(-1);
        }

        ret = xmlSecKeyX509DataValueXmlWriteString(x509Value->issuerSerial, issuerSerial,
            xmlSecNodeX509SerialNumber, xmlSecDSigNs);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecKeyX509DataValueXmlWriteString", NULL,
                "issuerSerial=%s", xmlSecErrorsSafeString(x509Value->issuerSerial));
            return(-1);
        }
    }
    if((!xmlSecBufferIsEmpty(&(x509Value->digest))) && (x509Value->digestAlgorithm != NULL)) {
        xmlNodePtr child;

        child = xmlSecKeyX509DataValueXmlWriteBase64Blob(&(x509Value->digest), node,
            xmlSecNodeX509Digest, xmlSecDSig11Ns,
            base64LineSize, addLineBreaks);
        if(child == NULL) {
            xmlSecInternalError("xmlSecKeyX509DataValueXmlWriteBase64Blob(digest)", NULL);
            return(-1);
        }

        if(xmlSetProp(child, xmlSecAttrAlgorithm, x509Value->digestAlgorithm) == NULL) {
            xmlSecXmlError2("xmlSetProp", NULL, "name=%s", xmlSecErrorsSafeString(xmlSecAttrAlgorithm));
            return(-1);
        }
    }
    return(0);
}

/**
 * @brief Reads X509 escaped string.
 * @details Reads X509 escaped string (see https://datatracker.ietf.org/doc/html/rfc4514#section-3).
 * The function parses the string in the @p in paramter until end of string or @p delim is encountered.
 * The @p in and @p inSize parameters are moved to the next character (e.g. delimeter if it was encountered
 * during parsing).
 * @param in the in/out pointer to the parsed string.
 * @param inSize the in/out size of the parsed string.
 * @param out the pointer to output string.
 * @param outSize the size of the output string.
 * @param outWritten the number of characters written to the output string.
 * @param delim the delimiter (stop char).
 * @param ingoreTrailingSpaces the flag indicating if trailing spaces should not be copied to output.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecX509EscapedStringRead(const xmlChar **in, xmlSecSize *inSize,
                        xmlSecByte *out, xmlSecSize outSize, xmlSecSize *outWritten,
                        xmlSecByte delim, int ingoreTrailingSpaces
) {
    xmlSecByte inCh, inFirstHex = 0;
    xmlSecSize ii, jj, nonSpaceJJ;
    int state = XMLSEC_X509_NAME_READ_STATE_NORMAL;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2((*in) != NULL, -1);
    xmlSecAssert2(inSize != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ii = jj = nonSpaceJJ = 0;
    while ((ii < (*inSize)) && (state != XMLSEC_X509_NAME_READ_STATE_DELIMETER)) {
        inCh = (*in)[ii];
        if (jj >= outSize) {
            xmlSecInvalidSizeOtherError("output buffer is too small", NULL);
            return(-1);
        }

        switch(state) {
        case XMLSEC_X509_NAME_READ_STATE_NORMAL:
            if (inCh == delim) {
                /* stop */
                state = XMLSEC_X509_NAME_READ_STATE_DELIMETER;
            } else if (inCh == '\\') {
                /* do not update output, move to next chat */
                state = XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH1;
                ++ii;
            } else {
                /* copy char and move to next */
                out[jj] = inCh;
                ++ii;
                ++jj;

                /* remember position of last non-spaceChar */
                if (ingoreTrailingSpaces && !isspace(inCh)) {
                    nonSpaceJJ = jj;
                }
            }
            break;
        case XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH1:
             /* if next char after \\ is a hex then we expect \\XX, otherwise we just remove \\ */
             if (xmlSecIsHex(inCh)) {
                inFirstHex = inCh;
                state = XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH2;
                ++ii;
             } else {
                /* just remove \\ */
                state = XMLSEC_X509_NAME_READ_STATE_NORMAL;

                /* copy char and move to next */
                out[jj] = inCh;
                ++ii;
                ++jj;

                /* remember position of last non-spaceChar */
                if (ingoreTrailingSpaces && !isspace(inCh)) {
                    nonSpaceJJ = jj;
                }
             }
            break;
        case XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH2:
            /* two XX chars are expected */
            if ((xmlSecIsHex(inCh)) && (inFirstHex > 0)) {
                state = XMLSEC_X509_NAME_READ_STATE_NORMAL;
                inCh = xmlSecFromHex2(inFirstHex, inCh);
                inFirstHex = 0;

                /* copy char and move to next */
                out[jj] = inCh;
                ++ii;
                ++jj;

                /* remember position of last non-spaceChar */
                if (ingoreTrailingSpaces && !isspace(inCh)) {
                    nonSpaceJJ = jj;
                }
            } else {
                xmlSecInvalidDataError("two hex digits expected", NULL);
                return(-1);
            }
            break;
        default:
            /* This should not be possible: logical error! */
            xmlSecInternalError2("", NULL, "invalid state=%d while parsing x509 name", state);
            return(-1);
        }
    }

    /* success */
    (*inSize) -= ii;
    (*in) += ii;
    if (ingoreTrailingSpaces != 0) {
        (*outWritten) = nonSpaceJJ;
    } else {
        (*outWritten) = (jj);
    }

    return(0);
}

/**
 * @brief Reads X509 attr value string.
 * @details Reads X509 attr value string (see https://datatracker.ietf.org/doc/html/rfc4514#section-3) of one of the
 * three types:
 *   - string (eg 'abc')
 *   - quoted string (eg '"abc"')
 *   - hexstring (eg '@p A0B0')
 * The function parses the string in the @p in paramter until end of string or @p delim is encountered.
 * The @p in and @p inSize parameters are moved to the next character (e.g. delimeter if it was encountered
 * during parsing).
 * @param in the in/out pointer to the parsed string.
 * @param inSize the in/out size of the parsed string.
 * @param out the pointer to output string.
 * @param outSize the size of the output string.
 * @param outWritten the number of characters written to the output string.
 * @param outType the type of string (UTF8 or octet).
 * @param delim the delimiter (stop char).
 * @param ingoreTrailingSpaces the flag indicating if trailing spaces should not be copied to output.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecX509AttrValueStringRead(
    const xmlChar **in,
    xmlSecSize *inSize,
    xmlSecByte *out,
    xmlSecSize outSize,
    xmlSecSize *outWritten,
    int *outType,
    xmlSecByte delim,
    int ingoreTrailingSpaces
) {
    int ret;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2((*in) != NULL, -1);
    xmlSecAssert2(inSize != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(0 < outSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);
    xmlSecAssert2(outType != NULL, -1);

    /* read value */
    if ((*inSize) == 0) {
        /* empty value */
        (*outWritten) = 0;
        (*outType) = XMLSEC_X509_VALUE_TYPE_UF8_STRING;
    } else if((**in) == '\"') {
        /* read quoted string */

        /* skip quote */
        ++(*in); --(*inSize);

        /* read string till next un-escaped quote */
        ret = xmlSecX509EscapedStringRead(in, inSize, out, outSize, outWritten, '\"', ingoreTrailingSpaces);
        if(ret < 0) {
            xmlSecInternalError("xmlSecX509EscapedStringRead", NULL);
            return(-1);
        }
        (*outType) = XMLSEC_X509_VALUE_TYPE_UF8_STRING;

        /* skip quote */
        if(((*inSize) <= 0) || ((**in) != '\"')) {
            xmlSecInvalidDataError("A double quote '\"' is expected at the end of the quoted string", NULL);
            return(-1);
        }
        ++(*in); --(*inSize);

        /* skip trailing spaces if needed */
        if(ingoreTrailingSpaces != 0) {
            while(((*inSize) > 0) && isspace(**in)) {
                ++(*in); --(*inSize);
            }
        }
    } else if((**in) == '#') {
        /* read octect value:
                hexstring = SHARP 1*hexpair
                hexpair = HEX HEX
        */
        xmlSecSize jj = 0;
        xmlChar hex1, hex2;

        /* skip sharp '#' */
        ++(*in); --(*inSize);

        /* process pair hex hex from input */
        while((jj < outSize) && ((*inSize) > 0) && (xmlSecIsHex(**in))) {
            /* we always expect pairs of hex digits*/
            if((*inSize) < 2) {
                xmlSecInvalidDataError("Expected two hex characters in octet string but got only one", NULL);
                return(-1);
            }
            hex1 = (**in); ++(*in); --(*inSize);
            hex2 = (**in); ++(*in); --(*inSize);
            if(!(xmlSecIsHex(hex2))) {
                xmlSecInvalidDataError("Expected two hex characters in octet string but second char is not hex", NULL);
                return(-1);
            }

            /* convert and save to output */
            out[jj] = xmlSecFromHex2(hex1, hex2);
            ++jj;
        }
        (*outWritten) = jj;
        (*outType) = XMLSEC_X509_VALUE_TYPE_OCTET_STRING;

        /* skip trailing spaces if needed */
        if(ingoreTrailingSpaces != 0) {
            while(((*inSize) > 0) && isspace(**in)) {
                ++(*in); --(*inSize);
            }
        }
    } else {
        /* read string */
        ret = xmlSecX509EscapedStringRead(in, inSize, out, outSize, outWritten, delim, ingoreTrailingSpaces);
        if(ret < 0) {
            xmlSecInternalError("xmlSecX509EscapedStringRead", NULL);
            return(-1);
        }
        (*outType) = XMLSEC_X509_VALUE_TYPE_UF8_STRING;
    }

    /* success */
    return(0);
}

/**
 * @brief Reads X509 name and calls callback on every found name/value pair.
 * @details Reads X509 name (see https://datatracker.ietf.org/doc/html/rfc4514#section-3) and calls
 * @p callback on every name / value pair found.
 * @param str the pointer to the parsed string.
 * @param replacements the optional replacements table (can be NULL).
 * @param callback the callback to be called on every found name / value pair.
 * @param context the context to be passed to callback.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecX509NameRead(const xmlChar *str, xmlSecx509NameReplacements *replacements, xmlSecX509NameReadCallback callback, void * context) {
    xmlSecByte name[XMLSEC_X509_NAME_SIZE];
    xmlSecByte value[XMLSEC_X509_VALUE_SIZE];
    xmlSecSize strSize, nameSize, valueSize;
    int type;
    int ret;

    xmlSecAssert2(str != NULL, -1);
    xmlSecAssert2(callback != NULL, -1);

    strSize = xmlSecStrlen(str);
    while(strSize > 0) {
        /* skip spaces after comma or semicolon */
        while((strSize > 0) && isspace(*str)) {
            ++str; --strSize;
        }

        /* read name */
        nameSize = 0;
        ret = xmlSecX509EscapedStringRead(&str, &strSize, name, sizeof(name) - 1, &nameSize, '=', 1);
        if(ret < 0) {
            xmlSecInternalError("xmlSecX509EscapedStringRead", NULL);
            return(-1);
        }
        xmlSecAssert2(nameSize < sizeof(name), -1);
        name[nameSize] = '\0';

        /* expect and skip '=' */
        if((strSize <= 0) || (*str != '=')) {
            xmlSecInvalidDataError("An equal sign '=' is expected between name and value", NULL);
            return(-1);
        }
        ++str; --strSize;

        /* skip spaces after '=' */
        while((strSize > 0) && isspace(*str)) {
            ++str; --strSize;
        }

        /* read value */
        ret = xmlSecX509AttrValueStringRead(&str, &strSize, value, sizeof(value) - 1, &valueSize, &type, ',', 1);
        if(ret < 0) {
            xmlSecInternalError("xmlSecX509EscapedStringRead", NULL);
            return(-1);
        }
        xmlSecAssert2(valueSize < sizeof(value), -1);
        value[valueSize] = '\0';


        /* handle replacements */
        if (replacements != NULL) {
            for(xmlSecx509NameReplacements *cur = replacements; (cur->original != NULL) && (cur->replacement != NULL); ++cur) {
                if (xmlStrcmp(name, cur->original) != 0) {
                    continue;
                }

                /* found replacement */
                ret = xmlStrPrintf(name, sizeof(name), "%s", cur->replacement);
                if(ret < 0) {
                    xmlSecInternalError("xmlStrPrintf()", NULL);
                    return(-1);
                }
                break;
             }
        }

        /* callback */
        ret = callback(name, value, valueSize, type, context);
        if(ret < 0) {
            xmlSecInternalError("xmlSecX509NameReadCallback", NULL);
            return(-1);
        }

        /* we expect either end of string or quote separating name / value pairs */
        if((strSize > 0) && ((*str) == ',')) {
            ++str; --strSize;
        } else if (strSize > 0) {
            xmlSecInvalidDataError("A quote ',' is expected between name and value pairs", NULL);
            return(-1);
        }
    }

    /* success */
    return(0);
}

/**
 * @brief Converts DER-encoded serial number to decimal string.
 * @details Converts a DER-encoded ASN.1 INTEGER (serial number) to its decimal string
 * representation.
 * @param data the serial number bytes (big-endian, unsigned).
 * @param dataSize the number of bytes in @p data.
 * @return the decimal string on success or NULL if an error occurs.
 * Caller is responsible for freeing the returned string with xmlFree().
 */
xmlChar*
xmlSecX509SerialNumberWrite(const xmlSecByte *data, xmlSecSize dataSize) {
    xmlChar *resString = NULL;
    unsigned char *workBytes = NULL;
    size_t workBytesLen;
    size_t resSize;
    size_t resLen;
    size_t ii;
    unsigned int carry;
    unsigned int remainder;
    int allZero;
    xmlChar *res = NULL;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 0, NULL);

    /* Skip leading 0x00 bytes: DER INTEGER encoding of positive values with MSB=1
     * requires a leading 0x00, so cert->serialNumber.len may be 21 for a 20-byte value. */
    while((dataSize > 1U) && (data[0] == 0x00U)) {
        ++data;
        --dataSize;
    }
    xmlSecAssert2(dataSize <= XMLSEC_X509_MAX_SERIAL_NUMBER_BYTES, NULL);

    workBytesLen = (size_t)dataSize;

    /* Allocate buffer for result */
    resSize = XMLSEC_X509_MAX_SERIAL_NUMBER_CHARS;
    resString = (xmlChar*)xmlMalloc(resSize);
    if(resString == NULL) {
        xmlSecMallocError(resSize, NULL);
        goto done;
    }
    memset(resString, 0, resSize);

    /* Make a working copy of bytes */
    workBytes = (unsigned char*)xmlMalloc(workBytesLen);
    if(workBytes == NULL) {
        xmlSecMallocError(workBytesLen, NULL);
        goto done;
    }
    memcpy(workBytes, data, workBytesLen);

    /* Build string from right to left using repeated division by 10 */
    resLen = 0;

    while(workBytesLen > 0) {
        /* Check if all bytes are zero */
        allZero = 1;
        for(ii = 0; ii < workBytesLen; ii++) {
            if(workBytes[ii] != 0) {
                allZero = 0;
                break;
            }
        }
        if(allZero) {
            break;
        }

        /* Divide by 10: for each byte, compute (carry * 256 + byte) / 10 */
        carry = 0;
        for(ii = 0; ii < workBytesLen; ii++) {
            remainder = carry * 256 + workBytes[ii];
            workBytes[ii] = (unsigned char)(remainder / 10);
            carry = remainder % 10;
        }

        /* Add remainder as digit (building string in reverse order) */
        if(resLen >= resSize - 1) {
            xmlSecInternalError("result buffer too small", NULL);
            goto done;
        }
        resString[resLen++] = (xmlChar)('0' + carry);

        /* Remove leading zeros from workBytes */
        while((workBytesLen > 0) && (workBytes[0] == 0)) {
            memmove(workBytes, workBytes + 1, workBytesLen - 1);
            workBytesLen--;
        }
    }

    /* If number was zero */
    if(resLen == 0) {
        resString[resLen++] = '0';
    }

    /* Reverse the string (since we built it backwards) */
    for(ii = 0; ii < (resLen / 2); ii++) {
        xmlChar tmp = resString[ii];
        size_t reverseIdx = resLen - 1 - (size_t)ii;
        resString[ii] = resString[reverseIdx];
        resString[reverseIdx] = tmp;
    }

    /* just to make sure */
    resString[resLen] = '\0';

    /* Done */
    res = resString;
    resString = NULL;

done:
    if(workBytes != NULL) {
        xmlFree(workBytes);
    }
    if(resString != NULL) {
        xmlFree(resString);
    }
    return(res);
}

/**
 * @brief Converts decimal string serial number to DER-encoded ASN.1 INTEGER bytes.
 * @details Converts a decimal string serial number to its DER-encoded ASN.1 INTEGER
 * byte representation (big-endian, with a leading 0x00 byte prepended when
 * the most-significant bit is set, per RFC 5280).
 * @param str the decimal string representation of the serial number.
 * @param res the output buffer for the DER-encoded big-endian bytes.
 * @param resSize the size of @p res in bytes (must be >= XMLSEC_X509_MAX_SERIAL_NUMBER_BYTES).
 * @param written the number of bytes written to @p res.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecX509SerialNumberRead(const xmlChar *str, xmlSecByte *res, xmlSecSize resSize, xmlSecSize *written) {
    unsigned char buf[XMLSEC_X509_MAX_SERIAL_NUMBER_BYTES];
    size_t start;
    size_t len;
    unsigned int idx;
    unsigned int digit;
    unsigned int carry;

    xmlSecAssert2(str != NULL, -1);
    xmlSecAssert2(res != NULL, -1);
    xmlSecAssert2(resSize >= XMLSEC_X509_MAX_SERIAL_NUMBER_BYTES, -1);
    xmlSecAssert2(written != NULL, -1);

    /* reject empty string */
    if(str[0] == '\0') {
        xmlSecInternalError("empty integer string", NULL);
        return(-1);
    }

    /* XMLSEC_X509_MAX_SERIAL_NUMBER_BYTES bytes can hold at most
     * XMLSEC_X509_MAX_SERIAL_NUMBER_CHARS decimal digits; reject anything longer
     * to avoid unnecessary CPU work on untrusted input */
    if(xmlStrlen(str) >= XMLSEC_X509_MAX_SERIAL_NUMBER_CHARS) {
        xmlSecInternalError("integer string is too long", NULL);
        return(-1);
    }

    memset(buf, 0, sizeof(buf));
    start = sizeof(buf) - 1;

    for(idx = 0; str[idx] != '\0'; ++idx) {
        if((str[idx] < '0') || (str[idx] > '9')) {
            xmlSecInternalError("invalid integer string", NULL);
            return(-1);
        }

        digit = (unsigned int)(str[idx] - '0');
        carry = digit;

        /* Multiply the current value by 10 and add the next decimal digit. */
        for(len = sizeof(buf); len > start; --len) {
            unsigned int value;

            value = ((unsigned int)buf[len - 1]) * 10U + carry;
            buf[len - 1] = (unsigned char)(value & 0xFFU);
            carry = value >> 8;
        }

        while(carry > 0U) {
            if(start == 0U) {
                xmlSecInternalError("integer value is too large", NULL);
                return(-1);
            }
            --start;
            buf[start] = (unsigned char)(carry & 0xFFU);
            carry >>= 8;
        }
    }

    /* Keep a single zero byte for the zero value. */
    while((start < (sizeof(buf) - 1U)) && (buf[start] == 0U)) {
        ++start;
    }

    /* ASN.1 INTEGER is signed: prepend 0x00 for positive values with MSB set. */
    if((buf[start] & 0x80U) != 0U) {
        if(start == 0U) {
            xmlSecInternalError("integer value is too large", NULL);
            return(-1);
        }
        --start;
        buf[start] = 0U;
    }

    /* start is always in [0, sizeof(buf)-1] at this point */
    xmlSecAssert2(start < sizeof(buf), -1);
    len = sizeof(buf) - start;
    xmlSecAssert2(len > 0, -1);

    memcpy(res, buf + start, len);
    (*written) = (xmlSecSize)len;
    return(0);
}

#else /* XMLSEC_NO_X509 */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_X509 */
