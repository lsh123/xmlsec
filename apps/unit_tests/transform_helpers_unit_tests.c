/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief XML Security Library transform helpers unit tests.
 */
#include <stdio.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "xmlsec_unit_tests.h"
#include <xmlsec/base64.h>
#include <xmlsec/strings.h>
#include <xmlsec/xmltree.h>
#include "../../src/transform_helpers.h"

 #if !defined(XMLSEC_NO_CHACHA20) || !defined(XMLSEC_NO_MLDSA) || !defined(XMLSEC_NO_SLHDSA) || !defined(XMLSEC_NO_EDDSA)
static xmlNodePtr
xmlSecUnitTestParseNode(const char* xml, xmlDocPtr* doc) {
    xmlNodePtr node;

    xmlSecAssert2(xml != NULL, NULL);
    xmlSecAssert2(doc != NULL, NULL);

    (*doc) = xmlReadMemory(xml, (int)strlen(xml), "transform-helpers.xml", NULL,
        XML_PARSE_NONET | XML_PARSE_NOBLANKS);
    if((*doc) == NULL) {
        testLog("Error: failed to parse XML\n");
        return(NULL);
    }

    node = xmlDocGetRootElement((*doc));
    if(node == NULL) {
        testLog("Error: parsed XML does not have a root node\n");
        xmlFreeDoc((*doc));
        (*doc) = NULL;
        return(NULL);
    }
    return(node);
}
#endif /* !defined(XMLSEC_NO_CHACHA20) || !defined(XMLSEC_NO_MLDSA) || !defined(XMLSEC_NO_SLHDSA) || !defined(XMLSEC_NO_EDDSA) */

#ifndef XMLSEC_NO_CHACHA20

static xmlNodePtr
xmlSecUnitTestFindChild(xmlNodePtr node, const xmlChar* name) {
    xmlNodePtr cur;

    xmlSecAssert2(node != NULL, NULL);
    xmlSecAssert2(name != NULL, NULL);

    for(cur = xmlSecGetNextElementNode(node->children); cur != NULL; cur = xmlSecGetNextElementNode(cur->next)) {
        if(xmlSecCheckNodeName(cur, name, xmlSecDSig2021MoreNs)) {
            return(cur);
        }
    }
    return(NULL);
}

static void
test_xmlSecTransformChaCha20ParamsRead_missing_nonce(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" "
        "xmlns:dsig-more=\"http://www.w3.org/2021/04/xmldsig-more#\">"
        "<dsig-more:Counter>01020304</dsig-more:Counter>"
        "</EncryptionMethod>";
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecByte iv[XMLSEC_CHACHA20_IV_SIZE];
    xmlSecSize ivSize = 0;
    int noncePresent = 1;
    int ret;

    testStart("ChaCha20 read missing nonce");

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    memset(iv, 0xFF, sizeof(iv));
    ret = xmlSecTransformChaCha20ParamsRead(node, iv, sizeof(iv), &ivSize, &noncePresent);
    if((ret < 0) || (ivSize != XMLSEC_CHACHA20_IV_SIZE) || (noncePresent != 0) ||
       (memcmp(iv, "\x01\x02\x03\x04", XMLSEC_CHACHA20_COUNTER_SIZE) != 0) ||
       (memcmp(iv + XMLSEC_CHACHA20_COUNTER_SIZE, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", XMLSEC_CHACHA20_NONCE_SIZE) != 0)) {
        testLog("Error: ChaCha20 params read did not accept missing nonce with required counter\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformChaCha20ParamsRead_missing_counter(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" "
        "xmlns:dsig-more=\"http://www.w3.org/2021/04/xmldsig-more#\">"
        "<dsig-more:Nonce>000102030405060708090a0b</dsig-more:Nonce>"
        "</EncryptionMethod>";
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecByte iv[XMLSEC_CHACHA20_IV_SIZE];
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    testStart("ChaCha20 read missing counter");

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    memset(iv, 0xFF, sizeof(iv));
    ret = xmlSecTransformChaCha20ParamsRead(node, iv, sizeof(iv), &ivSize, &noncePresent);
    if(ret >= 0) {
        testLog("Error: ChaCha20 params read accepted missing counter\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformChaCha20ParamsWrite_roundtrip(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\"/>";
    static const xmlSecByte iv[XMLSEC_CHACHA20_IV_SIZE] = {
        0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B
    };
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlNodePtr nonceNode;
    xmlNodePtr counterNode;
    xmlChar* nonceContent;
    xmlChar* counterContent;
    xmlSecByte ivRoundTrip[XMLSEC_CHACHA20_IV_SIZE];
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    testStart("ChaCha20 write roundtrip");

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    ret = xmlSecTransformChaCha20ParamsWrite(node, iv, sizeof(iv));
    if(ret < 0) {
        testLog("Error: failed to write ChaCha20 params\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    nonceNode = xmlSecUnitTestFindChild(node, xmlSecNodeChaCha20Nonce);
    counterNode = xmlSecUnitTestFindChild(node, xmlSecNodeChaCha20Counter);
    if((nonceNode == NULL) || (counterNode == NULL)) {
        testLog("Error: ChaCha20 params write did not create both nodes\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    nonceContent = xmlNodeGetContent(nonceNode);
    counterContent = xmlNodeGetContent(counterNode);
    if((nonceContent == NULL) || (counterContent == NULL) ||
       (xmlStrcmp(nonceContent, BAD_CAST "000102030405060708090a0b") != 0) ||
       (xmlStrcmp(counterContent, BAD_CAST "01020304") != 0)) {
        testLog("Error: ChaCha20 params write serialized unexpected values\n");
        xmlFree(nonceContent);
        xmlFree(counterContent);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFree(nonceContent);
    xmlFree(counterContent);

    ret = xmlSecTransformChaCha20ParamsRead(node, ivRoundTrip, sizeof(ivRoundTrip), &ivSize, &noncePresent);
    if((ret < 0) || (ivSize != XMLSEC_CHACHA20_IV_SIZE) || (noncePresent != 1) ||
       (memcmp(ivRoundTrip, iv, sizeof(iv)) != 0)) {
        testLog("Error: ChaCha20 params write did not round-trip through strict read\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformChaCha20Poly1305ParamsWrite_roundtrip(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\"/>";
    static const xmlSecByte iv[XMLSEC_CHACHA20_NONCE_SIZE] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B
    };
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlNodePtr nonceNode;
    xmlChar* nonceContent;
    xmlSecBuffer aad;
    xmlSecByte ivRoundTrip[XMLSEC_CHACHA20_NONCE_SIZE];
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    testStart("ChaCha20-Poly1305 write roundtrip");

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    ret = xmlSecTransformChaCha20Poly1305ParamsWrite(node, iv, sizeof(iv));
    if(ret < 0) {
        testLog("Error: failed to write ChaCha20-Poly1305 params\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    nonceNode = xmlSecUnitTestFindChild(node, xmlSecNodeChaCha20Nonce);
    if(nonceNode == NULL) {
        testLog("Error: ChaCha20-Poly1305 params write did not create nonce node\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    nonceContent = xmlNodeGetContent(nonceNode);
    if((nonceContent == NULL) || (xmlStrcmp(nonceContent, BAD_CAST "000102030405060708090a0b") != 0)) {
        testLog("Error: ChaCha20-Poly1305 params write serialized unexpected nonce\n");

        xmlFree(nonceContent);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFree(nonceContent);

    ret = xmlSecBufferInitialize(&aad, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize AAD buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = xmlSecTransformChaCha20Poly1305ParamsRead(node, &aad, ivRoundTrip, sizeof(ivRoundTrip), &ivSize, &noncePresent);
    xmlSecBufferFinalize(&aad);
    if((ret < 0) || (ivSize != XMLSEC_CHACHA20_NONCE_SIZE) || (noncePresent != 1) ||
       (memcmp(ivRoundTrip, iv, sizeof(iv)) != 0)) {
        testLog("Error: ChaCha20-Poly1305 params write did not round-trip through strict read\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformChaCha20Poly1305ParamsRead_missing_nonce(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\"/>";
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecBuffer aad;
    xmlSecByte iv[XMLSEC_CHACHA20_NONCE_SIZE];
    xmlSecSize ivSize = 0;
    int noncePresent = 1;
    int ret;

    testStart("ChaCha20-Poly1305 read missing nonce");

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&aad, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize AAD buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    memset(iv, 0xFF, sizeof(iv));
    ret = xmlSecTransformChaCha20Poly1305ParamsRead(node, &aad, iv, sizeof(iv), &ivSize, &noncePresent);
    xmlSecBufferFinalize(&aad);
    if((ret < 0) || (ivSize != XMLSEC_CHACHA20_NONCE_SIZE) || (noncePresent != 0) ||
       (memcmp(iv, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", XMLSEC_CHACHA20_NONCE_SIZE) != 0)) {
        testLog("Error: ChaCha20-Poly1305 params read did not accept missing nonce\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformChaCha20ParamsRead_invalid_nonce_hex_odd_length(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" "
        "xmlns:dsig-more=\"http://www.w3.org/2021/04/xmldsig-more#\">"
        "<dsig-more:Nonce>0102030</dsig-more:Nonce>"
        "<dsig-more:Counter>01020304</dsig-more:Counter>"
        "</EncryptionMethod>";
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecByte iv[XMLSEC_CHACHA20_IV_SIZE];
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    testStart("ChaCha20 read invalid nonce hex (odd length)");

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    memset(iv, 0xFF, sizeof(iv));
    ret = xmlSecTransformChaCha20ParamsRead(node, iv, sizeof(iv), &ivSize, &noncePresent);
    if(ret >= 0) {
        testLog("Error: ChaCha20 params read accepted nonce with odd-length hex content\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformChaCha20ParamsRead_invalid_nonce_hex_non_hex_chars(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" "
        "xmlns:dsig-more=\"http://www.w3.org/2021/04/xmldsig-more#\">"
        "<dsig-more:Nonce>0102zz0405060708090a0b</dsig-more:Nonce>"
        "<dsig-more:Counter>01020304</dsig-more:Counter>"
        "</EncryptionMethod>";
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecByte iv[XMLSEC_CHACHA20_IV_SIZE];
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    testStart("ChaCha20 read invalid nonce hex (non-hex characters)");

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    memset(iv, 0xFF, sizeof(iv));
    ret = xmlSecTransformChaCha20ParamsRead(node, iv, sizeof(iv), &ivSize, &noncePresent);
    if(ret >= 0) {
        testLog("Error: ChaCha20 params read accepted nonce with non-hex characters\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformChaCha20ParamsRead_invalid_nonce_size(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" "
        "xmlns:dsig-more=\"http://www.w3.org/2021/04/xmldsig-more#\">"
        "<dsig-more:Nonce>0102030405060708</dsig-more:Nonce>"
        "<dsig-more:Counter>01020304</dsig-more:Counter>"
        "</EncryptionMethod>";
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecByte iv[XMLSEC_CHACHA20_IV_SIZE];
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    testStart("ChaCha20 read invalid nonce size");

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    memset(iv, 0xFF, sizeof(iv));
    ret = xmlSecTransformChaCha20ParamsRead(node, iv, sizeof(iv), &ivSize, &noncePresent);
    if(ret >= 0) {
        testLog("Error: ChaCha20 params read accepted nonce of wrong size\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformChaCha20ParamsRead_invalid_counter_size(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" "
        "xmlns:dsig-more=\"http://www.w3.org/2021/04/xmldsig-more#\">"
        "<dsig-more:Nonce>000102030405060708090a0b</dsig-more:Nonce>"
        "<dsig-more:Counter>0102030405</dsig-more:Counter>"
        "</EncryptionMethod>";
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecByte iv[XMLSEC_CHACHA20_IV_SIZE];
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    testStart("ChaCha20 read invalid counter size");

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    memset(iv, 0xFF, sizeof(iv));
    ret = xmlSecTransformChaCha20ParamsRead(node, iv, sizeof(iv), &ivSize, &noncePresent);
    if(ret >= 0) {
        testLog("Error: ChaCha20 params read accepted counter of wrong size\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformChaCha20ParamsRead_unexpected_extra_child(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" "
        "xmlns:dsig-more=\"http://www.w3.org/2021/04/xmldsig-more#\">"
        "<dsig-more:Nonce>000102030405060708090a0b</dsig-more:Nonce>"
        "<dsig-more:Counter>01020304</dsig-more:Counter>"
        "<dsig-more:Extra>unexpected</dsig-more:Extra>"
        "</EncryptionMethod>";
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecByte iv[XMLSEC_CHACHA20_IV_SIZE];
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    testStart("ChaCha20 read unexpected extra child");

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    memset(iv, 0xFF, sizeof(iv));
    ret = xmlSecTransformChaCha20ParamsRead(node, iv, sizeof(iv), &ivSize, &noncePresent);
    if(ret >= 0) {
        testLog("Error: ChaCha20 params read accepted an unexpected extra child element\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformChaCha20ParamsRead_counter_before_nonce(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" "
        "xmlns:dsig-more=\"http://www.w3.org/2021/04/xmldsig-more#\">"
        "<dsig-more:Counter>01020304</dsig-more:Counter>"
        "<dsig-more:Nonce>000102030405060708090a0b</dsig-more:Nonce>"
        "</EncryptionMethod>";
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecByte iv[XMLSEC_CHACHA20_IV_SIZE];
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    testStart("ChaCha20 read counter before nonce");

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    memset(iv, 0xFF, sizeof(iv));
    ret = xmlSecTransformChaCha20ParamsRead(node, iv, sizeof(iv), &ivSize, &noncePresent);
    if(ret >= 0) {
        testLog("Error: ChaCha20 params read accepted counter appearing before nonce\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformChaCha20Poly1305ParamsRead_aad(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" "
        "xmlns:dsig-more=\"http://www.w3.org/2021/04/xmldsig-more#\">"
        "<dsig-more:Nonce>000102030405060708090a0b</dsig-more:Nonce>"
        "<dsig-more:AAD>0123456789abcdef</dsig-more:AAD>"
        "</EncryptionMethod>";
    static const xmlSecByte ivExpected[XMLSEC_CHACHA20_NONCE_SIZE] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B
    };
    static const char aadExpected[] = "0123456789abcdef";
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecBuffer aad;
    xmlSecByte iv[XMLSEC_CHACHA20_NONCE_SIZE];
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    testStart("ChaCha20-Poly1305 read AAD");

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&aad, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize AAD buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    memset(iv, 0xFF, sizeof(iv));
    ret = xmlSecTransformChaCha20Poly1305ParamsRead(node, &aad, iv, sizeof(iv), &ivSize, &noncePresent);
    if((ret < 0) || (ivSize != XMLSEC_CHACHA20_NONCE_SIZE) || (noncePresent != 1) ||
       (memcmp(iv, ivExpected, sizeof(ivExpected)) != 0)) {
        testLog("Error: ChaCha20-Poly1305 params read failed with AAD present\n");
        xmlSecBufferFinalize(&aad);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    if((xmlSecBufferGetSize(&aad) != (xmlSecSize)(sizeof(aadExpected) - 1)) ||
       (memcmp(xmlSecBufferGetData(&aad), aadExpected, sizeof(aadExpected) - 1) != 0)) {
        testLog("Error: ChaCha20-Poly1305 params read did not store AAD content into the buffer\n");
        xmlSecBufferFinalize(&aad);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&aad);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformChaCha20Poly1305ParamsRead_invalid_nonce_hex_odd_length(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" "
        "xmlns:dsig-more=\"http://www.w3.org/2021/04/xmldsig-more#\">"
        "<dsig-more:Nonce>0102030</dsig-more:Nonce>"
        "</EncryptionMethod>";
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecBuffer aad;
    xmlSecByte iv[XMLSEC_CHACHA20_NONCE_SIZE];
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    testStart("ChaCha20-Poly1305 read invalid nonce hex (odd length)");

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&aad, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize AAD buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    memset(iv, 0xFF, sizeof(iv));
    ret = xmlSecTransformChaCha20Poly1305ParamsRead(node, &aad, iv, sizeof(iv), &ivSize, &noncePresent);
    if(ret >= 0) {
        testLog("Error: ChaCha20-Poly1305 params read accepted nonce with odd-length hex content\n");
        xmlSecBufferFinalize(&aad);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&aad);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformChaCha20Poly1305ParamsRead_invalid_nonce_size(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" "
        "xmlns:dsig-more=\"http://www.w3.org/2021/04/xmldsig-more#\">"
        "<dsig-more:Nonce>0102030405060708</dsig-more:Nonce>"
        "</EncryptionMethod>";
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecBuffer aad;
    xmlSecByte iv[XMLSEC_CHACHA20_NONCE_SIZE];
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    testStart("ChaCha20-Poly1305 read invalid nonce size");

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&aad, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize AAD buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    memset(iv, 0xFF, sizeof(iv));
    ret = xmlSecTransformChaCha20Poly1305ParamsRead(node, &aad, iv, sizeof(iv), &ivSize, &noncePresent);
    if(ret >= 0) {
        testLog("Error: ChaCha20-Poly1305 params read accepted nonce of wrong size\n");
        xmlSecBufferFinalize(&aad);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&aad);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformChaCha20Poly1305ParamsRead_unexpected_extra_child(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" "
        "xmlns:dsig-more=\"http://www.w3.org/2021/04/xmldsig-more#\">"
        "<dsig-more:Nonce>000102030405060708090a0b</dsig-more:Nonce>"
        "<dsig-more:AAD>0123456789abcdef</dsig-more:AAD>"
        "<dsig-more:Extra>unexpected</dsig-more:Extra>"
        "</EncryptionMethod>";
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecBuffer aad;
    xmlSecByte iv[XMLSEC_CHACHA20_NONCE_SIZE];
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    testStart("ChaCha20-Poly1305 read unexpected extra child");

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&aad, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize AAD buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    memset(iv, 0xFF, sizeof(iv));
    ret = xmlSecTransformChaCha20Poly1305ParamsRead(node, &aad, iv, sizeof(iv), &ivSize, &noncePresent);
    if(ret >= 0) {
        testLog("Error: ChaCha20-Poly1305 params read accepted an unexpected extra child element\n");
        xmlSecBufferFinalize(&aad);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&aad);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

#endif /* XMLSEC_NO_CHACHA20 */

#ifndef XMLSEC_NO_HMAC

/******************************************************************************
 * xmlSecTransformHmacWriteOutput
 *****************************************************************************/
static void
test_xmlSecTransformHmacWriteOutput_empty_full_bytes(void) {
    static const xmlSecByte hmac[3] = { 0x12, 0x34, 0xAB };
    xmlSecBuffer buf;
    xmlSecByte* data;
    int ret;

    testStart("xmlSecTransformHmacWriteOutput: empty buffer, full byte length");

    ret = xmlSecBufferInitialize(&buf, 16);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        testFinishedFailure();
        return;
    }

    /* 16 bits => 2 bytes written */
    ret = xmlSecTransformHmacWriteOutput(hmac, 16, 3, &buf);
    if(ret < 0) {
        testLog("Error: xmlSecTransformHmacWriteOutput failed\n");
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }

    if(xmlSecBufferGetSize(&buf) != 2) {
        testLog("Error: expected buffer size 2, got %u\n", (unsigned)xmlSecBufferGetSize(&buf));
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }
    data = xmlSecBufferGetData(&buf);
    if((data == NULL) || (data[0] != 0x12) || (data[1] != 0x34)) {
        testLog("Error: expected bytes {0x12,0x34}, got {%02X,%02X}\n",
                data ? (unsigned)data[0] : 0, data ? (unsigned)data[1] : 0);
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
}

static void
test_xmlSecTransformHmacWriteOutput_empty_partial_bytes(void) {
    static const xmlSecByte hmac[3] = { 0x12, 0x34, 0xAB };
    xmlSecBuffer buf;
    xmlSecByte* data;
    int ret;

    testStart("xmlSecTransformHmacWriteOutput: empty buffer, partial byte masks last byte");

    ret = xmlSecBufferInitialize(&buf, 16);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        testFinishedFailure();
        return;
    }

    /* 12 bits => 2 bytes written, last byte masked with 0xF0 (0x34 & 0xF0 = 0x30) */
    ret = xmlSecTransformHmacWriteOutput(hmac, 12, 3, &buf);
    if(ret < 0) {
        testLog("Error: xmlSecTransformHmacWriteOutput failed\n");
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }

    if(xmlSecBufferGetSize(&buf) != 2) {
        testLog("Error: expected buffer size 2, got %u\n", (unsigned)xmlSecBufferGetSize(&buf));
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }
    data = xmlSecBufferGetData(&buf);
    if((data == NULL) || (data[0] != 0x12) || (data[1] != 0x30)) {
        testLog("Error: expected bytes {0x12,0x30}, got {%02X,%02X}\n",
                data ? (unsigned)data[0] : 0, data ? (unsigned)data[1] : 0);
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
}

static void
test_xmlSecTransformHmacWriteOutput_prefilled_partial_bytes(void) {
    static const xmlSecByte hmac[3] = { 0x12, 0x34, 0xAB };
    static const xmlSecByte prefill[2] = { 0xAA, 0xBB };
    xmlSecBuffer buf;
    xmlSecByte* data;
    int ret;

    testStart("xmlSecTransformHmacWriteOutput: prefilled buffer masks appended last byte only");

    ret = xmlSecBufferInitialize(&buf, 16);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferAppend(&buf, prefill, sizeof(prefill));
    if(ret < 0) {
        testLog("Error: failed to prefill buffer\n");
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }

    /* 12 bits => 2 bytes appended after the 2 prefilled bytes.
     * The last byte of the *appended* HMAC (index 3) must be masked with 0xF0,
     * while the prefilled bytes (indices 0..1) must remain untouched. */
    ret = xmlSecTransformHmacWriteOutput(hmac, 12, 3, &buf);
    if(ret < 0) {
        testLog("Error: xmlSecTransformHmacWriteOutput failed\n");
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }

    if(xmlSecBufferGetSize(&buf) != 4) {
        testLog("Error: expected buffer size 4, got %u\n", (unsigned)xmlSecBufferGetSize(&buf));
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }
    data = xmlSecBufferGetData(&buf);
    if((data == NULL) || (data[0] != 0xAA) || (data[1] != 0xBB) ||
       (data[2] != 0x12) || (data[3] != 0x30)) {
        testLog("Error: expected bytes {AA,BB,12,30}, got {%02X,%02X,%02X,%02X}\n",
                data ? (unsigned)data[0] : 0, data ? (unsigned)data[1] : 0,
                data ? (unsigned)data[2] : 0, data ? (unsigned)data[3] : 0);
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
}

static void
test_xmlSecTransformHmacWriteOutput_prefilled_full_bytes(void) {
    static const xmlSecByte hmac[2] = { 0x12, 0x34 };
    static const xmlSecByte prefill[1] = { 0xAA };
    xmlSecBuffer buf;
    xmlSecByte* data;
    int ret;

    testStart("xmlSecTransformHmacWriteOutput: prefilled buffer, full byte length");

    ret = xmlSecBufferInitialize(&buf, 16);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferAppend(&buf, prefill, sizeof(prefill));
    if(ret < 0) {
        testLog("Error: failed to prefill buffer\n");
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }

    /* 16 bits => 2 bytes appended after the 1 prefilled byte */
    ret = xmlSecTransformHmacWriteOutput(hmac, 16, 2, &buf);
    if(ret < 0) {
        testLog("Error: xmlSecTransformHmacWriteOutput failed\n");
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }

    if(xmlSecBufferGetSize(&buf) != 3) {
        testLog("Error: expected buffer size 3, got %u\n", (unsigned)xmlSecBufferGetSize(&buf));
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }
    data = xmlSecBufferGetData(&buf);
    if((data == NULL) || (data[0] != 0xAA) || (data[1] != 0x12) || (data[2] != 0x34)) {
        testLog("Error: expected bytes {AA,12,34}, got {%02X,%02X,%02X}\n",
                data ? (unsigned)data[0] : 0, data ? (unsigned)data[1] : 0, data ? (unsigned)data[2] : 0);
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
}

#endif /* XMLSEC_NO_HMAC */

#if !defined(XMLSEC_NO_MLDSA) || !defined(XMLSEC_NO_SLHDSA) || !defined(XMLSEC_NO_EDDSA)

/******************************************************************************
 * xmlSecTransformMLDSAReadContextString / xmlSecTransformSLHDSAReadContextString /
 * xmlSecTransformEdDSAReadContextString
 *
 * All three functions read a base64 encoded context string either from the
 * first child of a <SignatureMethod> element or from a <ds:Object> element
 * of the containing <ds:Signature> element. They are identical apart from
 * the maximum allowed context string size, so the tests below are shared
 * and parameterized by the reader function and the expected limits.
 *****************************************************************************/

#define XMLSEC_UNIT_TEST_DSIG_NS_URI      "http://www.w3.org/2000/09/xmldsig#"
#define XMLSEC_UNIT_TEST_CONTEXT_NS_URI   "http://www.w3.org/2026/08/xmldsig-more#"
#define XMLSEC_UNIT_TEST_WRONG_NS_URI     "http://www.w3.org/2021/04/xmldsig-more#"
#define XMLSEC_UNIT_TEST_CONTEXT_B64      "AQIDBA=="
#define XMLSEC_UNIT_TEST_XML_BUF_SIZE     1024

/* "AQIDBA==" is the base64 encoding of { 0x01, 0x02, 0x03, 0x04 } */
static const xmlSecByte g_unitTestContextBytes[] = { 0x01, 0x02, 0x03, 0x04 };

typedef int (*xmlSecUnitTestContextStringReadFunc)(xmlNodePtr node, xmlSecBufferPtr res);

typedef struct xmlSecUnitTestContextStringParams {
    const char* label;
    const char* algorithm;
    xmlSecSize maxSize;
    xmlSecUnitTestContextStringReadFunc readFunc;
} xmlSecUnitTestContextStringParams;

/*
 * Starts a test with a name of "<label> read: <suffix>". testStart() keeps a
 * pointer to the name, so the name is built in a static buffer; the harness
 * runs the tests sequentially, so this is safe. If the combined name does
 * not fit into the buffer, the label alone is used to start the test and the
 * test is marked as failed.
 */
static void
xmlSecUnitTestStartTest(const char* label, const char* suffix) {
    static char name[128];
    int ret;

    ret = snprintf(name, sizeof(name), "%s read: %s", label, suffix);
    if((ret < 0) || ((size_t)ret >= sizeof(name))) {
        testStart(label);
        testLog("Error: failed to build test name\n");
        testFinishedFailure();
        return;
    }
    testStart(name);
}

/*
 * Builds the XML for a <SignatureContext> element with the given namespace
 * and base64 encoded content. Returns 0 on success and a negative value if
 * the result does not fit into the output buffer.
 */
static int
xmlSecUnitTestBuildContextElementXml(const char* nsUri, const char* content,
    char* buf, size_t bufSize) {
    int ret;

    ret = snprintf(buf, bufSize, "<SignatureContext xmlns=\"%s\">%s</SignatureContext>",
        nsUri, content);
    if((ret < 0) || ((size_t)ret >= bufSize)) {
        return(-1);
    }
    return(0);
}

/*
 * Builds the XML for a <SignatureMethod> element with the given Algorithm
 * attribute and content. Returns 0 on success and a negative value if the
 * result does not fit into the output buffer.
 */
static int
xmlSecUnitTestBuildSignatureMethodXml(const char* algorithm, const char* content,
    char* buf, size_t bufSize) {
    int ret;

    ret = snprintf(buf, bufSize, "<SignatureMethod Algorithm=\"%s\">%s</SignatureMethod>",
        algorithm, content);
    if((ret < 0) || ((size_t)ret >= bufSize)) {
        return(-1);
    }
    return(0);
}

/*
 * Builds the XML for a <ds:Signature> element with a <ds:SignedInfo>
 * containing a <SignatureMethod> element with the given content and a
 * <ds:Object> element with the given content. Returns 0 on success and a
 * negative value if the result does not fit into the output buffer.
 */
static int
xmlSecUnitTestBuildObjectSignatureXml(const char* algorithm, const char* methodContent,
    const char* objectContent, char* buf, size_t bufSize) {
    int ret;

    ret = snprintf(buf, bufSize,
        "<ds:Signature xmlns:ds=\"" XMLSEC_UNIT_TEST_DSIG_NS_URI "\">"
        "<ds:SignedInfo>"
        "<ds:SignatureMethod Algorithm=\"%s\">%s</ds:SignatureMethod>"
        "</ds:SignedInfo>"
        "<ds:SignatureValue>dummy</ds:SignatureValue>"
        "<ds:Object>%s</ds:Object>"
        "</ds:Signature>",
        algorithm, methodContent, objectContent);
    if((ret < 0) || ((size_t)ret >= bufSize)) {
        return(-1);
    }
    return(0);
}

/*
 * Builds a NUL-terminated base64 encoded string for the first @p size bytes
 * of the test payload (byte i is (xmlSecByte)i). The caller is responsible
 * for freeing the returned string using xmlFree(). Returns NULL on error.
 */
static char*
xmlSecUnitTestBuildBase64Payload(xmlSecSize size) {
    xmlSecByte data[256];
    int ii;
    xmlChar* encoded;

    xmlSecAssert2(size <= 256, NULL);

    for(ii = 0; ii < 256; ii++) {
        data[ii] = (xmlSecByte)ii;
    }
    encoded = xmlSecBase64Encode(data, size, 0);
    return((char*)encoded);
}

static void
test_xmlSecTransformContextStringRead_null_node(const xmlSecUnitTestContextStringParams* params) {
    xmlSecBuffer buf;
    int ret;

    xmlSecUnitTestStartTest(params->label, "null node");

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        testFinishedFailure();
        return;
    }

    ret = params->readFunc(NULL, &buf);
    if(ret >= 0) {
        testLog("Error: read accepted a NULL node\n");
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
}

static void
test_xmlSecTransformContextStringRead_null_buffer(const xmlSecUnitTestContextStringParams* params) {
    char contextXml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    char xml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    int ret;

    xmlSecUnitTestStartTest(params->label, "null buffer");

    ret = xmlSecUnitTestBuildContextElementXml(XMLSEC_UNIT_TEST_CONTEXT_NS_URI,
        XMLSEC_UNIT_TEST_CONTEXT_B64, contextXml, sizeof(contextXml));
    if(ret < 0) {
        testLog("Error: failed to build context element XML\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecUnitTestBuildSignatureMethodXml(params->algorithm, contextXml, xml, sizeof(xml));
    if(ret < 0) {
        testLog("Error: failed to build SignatureMethod XML\n");
        testFinishedFailure();
        return;
    }

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    ret = params->readFunc(node, NULL);
    if(ret >= 0) {
        testLog("Error: read accepted a NULL buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformContextStringRead_no_context(const xmlSecUnitTestContextStringParams* params) {
    char xml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecBuffer buf;
    int ret;

    xmlSecUnitTestStartTest(params->label, "no context string");

    ret = xmlSecUnitTestBuildSignatureMethodXml(params->algorithm, "", xml, sizeof(xml));
    if(ret < 0) {
        testLog("Error: failed to build SignatureMethod XML\n");
        testFinishedFailure();
        return;
    }

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = params->readFunc(node, &buf);
    if((ret != 0) || !xmlSecBufferIsEmpty(&buf)) {
        testLog("Error: read of a SignatureMethod without a context string failed or filled the buffer\n");
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&buf);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformContextStringRead_signature_method(const xmlSecUnitTestContextStringParams* params) {
    char contextXml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    char xml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecBuffer buf;
    const xmlSecByte* data;
    int ret;

    xmlSecUnitTestStartTest(params->label, "valid context string in SignatureMethod");

    ret = xmlSecUnitTestBuildContextElementXml(XMLSEC_UNIT_TEST_CONTEXT_NS_URI,
        XMLSEC_UNIT_TEST_CONTEXT_B64, contextXml, sizeof(contextXml));
    if(ret < 0) {
        testLog("Error: failed to build context element XML\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecUnitTestBuildSignatureMethodXml(params->algorithm, contextXml, xml, sizeof(xml));
    if(ret < 0) {
        testLog("Error: failed to build SignatureMethod XML\n");
        testFinishedFailure();
        return;
    }

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = params->readFunc(node, &buf);
    if(ret < 0) {
        testLog("Error: failed to read context string from SignatureMethod\n");
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    if(xmlSecBufferGetSize(&buf) != sizeof(g_unitTestContextBytes)) {
        testLog("Error: expected buffer size %u, got %u\n",
            (unsigned)sizeof(g_unitTestContextBytes), (unsigned)xmlSecBufferGetSize(&buf));
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    data = xmlSecBufferGetData(&buf);
    if((data == NULL) || (memcmp(data, g_unitTestContextBytes, sizeof(g_unitTestContextBytes)) != 0)) {
        testLog("Error: read context string does not match the expected value\n");
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&buf);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformContextStringRead_signature_method_max_size(const xmlSecUnitTestContextStringParams* params) {
    char* contextB64 = NULL;
    char contextXml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    char xml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecBuffer buf;
    int ret;

    xmlSecUnitTestStartTest(params->label, "SignatureMethod context string at max size");

    contextB64 = xmlSecUnitTestBuildBase64Payload(params->maxSize);
    if(contextB64 == NULL) {
        testLog("Error: failed to build base64 payload\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecUnitTestBuildContextElementXml(XMLSEC_UNIT_TEST_CONTEXT_NS_URI,
        contextB64, contextXml, sizeof(contextXml));
    if(ret < 0) {
        testLog("Error: failed to build context element XML\n");
        xmlFree(contextB64);
        testFinishedFailure();
        return;
    }

    ret = xmlSecUnitTestBuildSignatureMethodXml(params->algorithm, contextXml, xml, sizeof(xml));
    if(ret < 0) {
        testLog("Error: failed to build SignatureMethod XML\n");
        xmlFree(contextB64);
        testFinishedFailure();
        return;
    }

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        xmlFree(contextB64);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        xmlFree(contextB64);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = params->readFunc(node, &buf);
    if(ret < 0) {
        testLog("Error: failed to read max size context string from SignatureMethod\n");
        xmlFree(contextB64);
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    if(xmlSecBufferGetSize(&buf) != params->maxSize) {
        testLog("Error: expected buffer size " XMLSEC_SIZE_FMT ", got " XMLSEC_SIZE_FMT "\n",
            params->maxSize, xmlSecBufferGetSize(&buf));
        xmlFree(contextB64);
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFree(contextB64);
    xmlSecBufferFinalize(&buf);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformContextStringRead_signature_method_exceeds_max(const xmlSecUnitTestContextStringParams* params) {
    char* contextB64 = NULL;
    char contextXml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    char xml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecBuffer buf;
    int ret;

    xmlSecUnitTestStartTest(params->label, "SignatureMethod context string exceeds max size");

    contextB64 = xmlSecUnitTestBuildBase64Payload(params->maxSize + 1);
    if(contextB64 == NULL) {
        testLog("Error: failed to build base64 payload\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecUnitTestBuildContextElementXml(XMLSEC_UNIT_TEST_CONTEXT_NS_URI,
        contextB64, contextXml, sizeof(contextXml));
    if(ret < 0) {
        testLog("Error: failed to build context element XML\n");
        xmlFree(contextB64);
        testFinishedFailure();
        return;
    }

    ret = xmlSecUnitTestBuildSignatureMethodXml(params->algorithm, contextXml, xml, sizeof(xml));
    if(ret < 0) {
        testLog("Error: failed to build SignatureMethod XML\n");
        xmlFree(contextB64);
        testFinishedFailure();
        return;
    }

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        xmlFree(contextB64);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        xmlFree(contextB64);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = params->readFunc(node, &buf);
    if(ret >= 0) {
        testLog("Error: read accepted a context string exceeding the max size\n");
        xmlFree(contextB64);
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFree(contextB64);
    xmlSecBufferFinalize(&buf);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformContextStringRead_invalid_base64(const xmlSecUnitTestContextStringParams* params) {
    char contextXml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    char xml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecBuffer buf;
    int ret;

    xmlSecUnitTestStartTest(params->label, "invalid base64 content in SignatureMethod");

    ret = xmlSecUnitTestBuildContextElementXml(XMLSEC_UNIT_TEST_CONTEXT_NS_URI,
        "QQ!Q", contextXml, sizeof(contextXml));
    if(ret < 0) {
        testLog("Error: failed to build context element XML\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecUnitTestBuildSignatureMethodXml(params->algorithm, contextXml, xml, sizeof(xml));
    if(ret < 0) {
        testLog("Error: failed to build SignatureMethod XML\n");
        testFinishedFailure();
        return;
    }

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = params->readFunc(node, &buf);
    if(ret >= 0) {
        testLog("Error: read accepted invalid base64 content\n");
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&buf);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformContextStringRead_unexpected_first_child(const xmlSecUnitTestContextStringParams* params) {
    const char* extraXml = "<Extra xmlns=\"" XMLSEC_UNIT_TEST_DSIG_NS_URI "\">unexpected</Extra>";
    char xml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecBuffer buf;
    int ret;

    xmlSecUnitTestStartTest(params->label, "unexpected first child in SignatureMethod");

    ret = xmlSecUnitTestBuildSignatureMethodXml(params->algorithm, extraXml, xml, sizeof(xml));
    if(ret < 0) {
        testLog("Error: failed to build SignatureMethod XML\n");
        testFinishedFailure();
        return;
    }

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = params->readFunc(node, &buf);
    if(ret >= 0) {
        testLog("Error: read accepted an unexpected first child element\n");
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&buf);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformContextStringRead_extra_child_after_context(const xmlSecUnitTestContextStringParams* params) {
    const char* extraXml = "<Extra xmlns=\"" XMLSEC_UNIT_TEST_DSIG_NS_URI "\">unexpected</Extra>";
    char contextXml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    char innerXml[2 * XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    char xml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecBuffer buf;
    int ret;

    xmlSecUnitTestStartTest(params->label, "extra child after context string in SignatureMethod");

    ret = xmlSecUnitTestBuildContextElementXml(XMLSEC_UNIT_TEST_CONTEXT_NS_URI,
        XMLSEC_UNIT_TEST_CONTEXT_B64, contextXml, sizeof(contextXml));
    if(ret < 0) {
        testLog("Error: failed to build context element XML\n");
        testFinishedFailure();
        return;
    }

    ret = snprintf(innerXml, sizeof(innerXml), "%s%s", contextXml, extraXml);
    if((ret < 0) || ((size_t)ret >= sizeof(innerXml))) {
        testLog("Error: failed to build SignatureMethod content XML\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecUnitTestBuildSignatureMethodXml(params->algorithm, innerXml, xml, sizeof(xml));
    if(ret < 0) {
        testLog("Error: failed to build SignatureMethod XML\n");
        testFinishedFailure();
        return;
    }

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = params->readFunc(node, &buf);
    if(ret >= 0) {
        testLog("Error: read accepted an extra child element after the context string\n");
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&buf);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformContextStringRead_wrong_namespace(const xmlSecUnitTestContextStringParams* params) {
    char contextXml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    char xml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecBuffer buf;
    int ret;

    xmlSecUnitTestStartTest(params->label, "context string with wrong namespace");

    ret = xmlSecUnitTestBuildContextElementXml(XMLSEC_UNIT_TEST_WRONG_NS_URI,
        XMLSEC_UNIT_TEST_CONTEXT_B64, contextXml, sizeof(contextXml));
    if(ret < 0) {
        testLog("Error: failed to build context element XML\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecUnitTestBuildSignatureMethodXml(params->algorithm, contextXml, xml, sizeof(xml));
    if(ret < 0) {
        testLog("Error: failed to build SignatureMethod XML\n");
        testFinishedFailure();
        return;
    }

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = params->readFunc(node, &buf);
    if(ret >= 0) {
        testLog("Error: read accepted a context string element with a wrong namespace\n");
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&buf);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformContextStringRead_object(const xmlSecUnitTestContextStringParams* params) {
    char contextXml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    char xml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlNodePtr signedInfo;
    xmlNodePtr signatureMethodNode;
    xmlSecBuffer buf;
    const xmlSecByte* data;
    int ret;

    xmlSecUnitTestStartTest(params->label, "valid context string in Object");

    ret = xmlSecUnitTestBuildContextElementXml(XMLSEC_UNIT_TEST_CONTEXT_NS_URI,
        XMLSEC_UNIT_TEST_CONTEXT_B64, contextXml, sizeof(contextXml));
    if(ret < 0) {
        testLog("Error: failed to build context element XML\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecUnitTestBuildObjectSignatureXml(params->algorithm, "", contextXml, xml, sizeof(xml));
    if(ret < 0) {
        testLog("Error: failed to build Signature XML\n");
        testFinishedFailure();
        return;
    }

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    /* locate the <SignatureMethod> element: Signature -> SignedInfo -> SignatureMethod */
    signedInfo = xmlSecGetNextElementNode(node->children);
    signatureMethodNode = (signedInfo != NULL) ? xmlSecGetNextElementNode(signedInfo->children) : NULL;
    if(signatureMethodNode == NULL) {
        testLog("Error: failed to locate the SignatureMethod node\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = params->readFunc(signatureMethodNode, &buf);
    if(ret < 0) {
        testLog("Error: failed to read context string from Object\n");
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    if(xmlSecBufferGetSize(&buf) != sizeof(g_unitTestContextBytes)) {
        testLog("Error: expected buffer size %u, got %u\n",
            (unsigned)sizeof(g_unitTestContextBytes), (unsigned)xmlSecBufferGetSize(&buf));
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    data = xmlSecBufferGetData(&buf);
    if((data == NULL) || (memcmp(data, g_unitTestContextBytes, sizeof(g_unitTestContextBytes)) != 0)) {
        testLog("Error: read context string does not match the expected value\n");
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&buf);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformContextStringRead_object_exceeds_max(const xmlSecUnitTestContextStringParams* params) {
    char* contextB64 = NULL;
    char contextXml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    char xml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlNodePtr signedInfo;
    xmlNodePtr signatureMethodNode;
    xmlSecBuffer buf;
    int ret;

    xmlSecUnitTestStartTest(params->label, "Object context string exceeds max size");

    contextB64 = xmlSecUnitTestBuildBase64Payload(params->maxSize + 1);
    if(contextB64 == NULL) {
        testLog("Error: failed to build base64 payload\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecUnitTestBuildContextElementXml(XMLSEC_UNIT_TEST_CONTEXT_NS_URI,
        contextB64, contextXml, sizeof(contextXml));
    if(ret < 0) {
        testLog("Error: failed to build context element XML\n");
        xmlFree(contextB64);
        testFinishedFailure();
        return;
    }

    ret = xmlSecUnitTestBuildObjectSignatureXml(params->algorithm, "", contextXml, xml, sizeof(xml));
    if(ret < 0) {
        testLog("Error: failed to build Signature XML\n");
        xmlFree(contextB64);
        testFinishedFailure();
        return;
    }

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        xmlFree(contextB64);
        testFinishedFailure();
        return;
    }

    /* locate the <SignatureMethod> element: Signature -> SignedInfo -> SignatureMethod */
    signedInfo = xmlSecGetNextElementNode(node->children);
    signatureMethodNode = (signedInfo != NULL) ? xmlSecGetNextElementNode(signedInfo->children) : NULL;
    if(signatureMethodNode == NULL) {
        testLog("Error: failed to locate the SignatureMethod node\n");
        xmlFree(contextB64);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        xmlFree(contextB64);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = params->readFunc(signatureMethodNode, &buf);
    if(ret >= 0) {
        testLog("Error: read accepted a context string exceeding the max size\n");
        xmlFree(contextB64);
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFree(contextB64);
    xmlSecBufferFinalize(&buf);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformContextStringRead_both_method_and_object(const xmlSecUnitTestContextStringParams* params) {
    char contextXml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    char xml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlNodePtr signedInfo;
    xmlNodePtr signatureMethodNode;
    xmlSecBuffer buf;
    int ret;

    xmlSecUnitTestStartTest(params->label, "context strings in both SignatureMethod and Object");

    ret = xmlSecUnitTestBuildContextElementXml(XMLSEC_UNIT_TEST_CONTEXT_NS_URI,
        XMLSEC_UNIT_TEST_CONTEXT_B64, contextXml, sizeof(contextXml));
    if(ret < 0) {
        testLog("Error: failed to build context element XML\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecUnitTestBuildObjectSignatureXml(params->algorithm, contextXml, contextXml, xml, sizeof(xml));
    if(ret < 0) {
        testLog("Error: failed to build Signature XML\n");
        testFinishedFailure();
        return;
    }

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    /* locate the <SignatureMethod> element: Signature -> SignedInfo -> SignatureMethod */
    signedInfo = xmlSecGetNextElementNode(node->children);
    signatureMethodNode = (signedInfo != NULL) ? xmlSecGetNextElementNode(signedInfo->children) : NULL;
    if(signatureMethodNode == NULL) {
        testLog("Error: failed to locate the SignatureMethod node\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = params->readFunc(signatureMethodNode, &buf);
    if(ret >= 0) {
        testLog("Error: read accepted context strings in both SignatureMethod and Object\n");
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&buf);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTransformContextStringRead_non_empty_buffer(const xmlSecUnitTestContextStringParams* params) {
    static const xmlSecByte prefill[] = { 0x01 };
    char xml[XMLSEC_UNIT_TEST_XML_BUF_SIZE];
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecBuffer buf;
    int ret;

    xmlSecUnitTestStartTest(params->label, "non-empty result buffer");

    ret = xmlSecUnitTestBuildSignatureMethodXml(params->algorithm, "", xml, sizeof(xml));
    if(ret < 0) {
        testLog("Error: failed to build SignatureMethod XML\n");
        testFinishedFailure();
        return;
    }

    node = xmlSecUnitTestParseNode(xml, &doc);
    if(node == NULL) {
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferAppend(&buf, prefill, sizeof(prefill));
    if(ret < 0) {
        testLog("Error: failed to prefill buffer\n");
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = params->readFunc(node, &buf);
    if(ret >= 0) {
        testLog("Error: read accepted a non-empty result buffer\n");
        xmlSecBufferFinalize(&buf);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&buf);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

#endif /* !XMLSEC_NO_MLDSA || !XMLSEC_NO_SLHDSA || !XMLSEC_NO_EDDSA */

int
test_transform_helpers(void) {
    int success = 1;

#ifndef XMLSEC_NO_CHACHA20
    testGroupStart("transform helpers");

    test_xmlSecTransformChaCha20ParamsRead_missing_nonce();
    test_xmlSecTransformChaCha20ParamsRead_missing_counter();
    test_xmlSecTransformChaCha20ParamsWrite_roundtrip();
    test_xmlSecTransformChaCha20ParamsRead_invalid_nonce_hex_odd_length();
    test_xmlSecTransformChaCha20ParamsRead_invalid_nonce_hex_non_hex_chars();
    test_xmlSecTransformChaCha20ParamsRead_invalid_nonce_size();
    test_xmlSecTransformChaCha20ParamsRead_invalid_counter_size();
    test_xmlSecTransformChaCha20ParamsRead_unexpected_extra_child();
    test_xmlSecTransformChaCha20ParamsRead_counter_before_nonce();
    test_xmlSecTransformChaCha20Poly1305ParamsRead_missing_nonce();
    test_xmlSecTransformChaCha20Poly1305ParamsWrite_roundtrip();
    test_xmlSecTransformChaCha20Poly1305ParamsRead_aad();
    test_xmlSecTransformChaCha20Poly1305ParamsRead_invalid_nonce_hex_odd_length();
    test_xmlSecTransformChaCha20Poly1305ParamsRead_invalid_nonce_size();
    test_xmlSecTransformChaCha20Poly1305ParamsRead_unexpected_extra_child();

    if(testGroupFinished() != 1) { success = 0; }
#endif /* XMLSEC_NO_CHACHA20 */

#ifndef XMLSEC_NO_HMAC
    testGroupStart("xmlSecTransformHmacWriteOutput");

    test_xmlSecTransformHmacWriteOutput_empty_full_bytes();
    test_xmlSecTransformHmacWriteOutput_empty_partial_bytes();
    test_xmlSecTransformHmacWriteOutput_prefilled_partial_bytes();
    test_xmlSecTransformHmacWriteOutput_prefilled_full_bytes();

    if(testGroupFinished() != 1) { success = 0; }
#endif /* XMLSEC_NO_HMAC */

#if !defined(XMLSEC_NO_MLDSA) || !defined(XMLSEC_NO_SLHDSA) || !defined(XMLSEC_NO_EDDSA)
#ifndef XMLSEC_NO_MLDSA
    {
        const xmlSecUnitTestContextStringParams mldsaParams = {
            "ML-DSA",
            "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-44",
            XMLSEC_MLDSA_MAX_SIZE,
            xmlSecTransformMLDSAReadContextString
        };

        testGroupStart("xmlSecTransformMLDSAReadContextString");

        test_xmlSecTransformContextStringRead_null_node(&mldsaParams);
        test_xmlSecTransformContextStringRead_null_buffer(&mldsaParams);
        test_xmlSecTransformContextStringRead_no_context(&mldsaParams);
        test_xmlSecTransformContextStringRead_signature_method(&mldsaParams);
        test_xmlSecTransformContextStringRead_signature_method_max_size(&mldsaParams);
        test_xmlSecTransformContextStringRead_signature_method_exceeds_max(&mldsaParams);
        test_xmlSecTransformContextStringRead_invalid_base64(&mldsaParams);
        test_xmlSecTransformContextStringRead_unexpected_first_child(&mldsaParams);
        test_xmlSecTransformContextStringRead_extra_child_after_context(&mldsaParams);
        test_xmlSecTransformContextStringRead_wrong_namespace(&mldsaParams);
        test_xmlSecTransformContextStringRead_object(&mldsaParams);
        test_xmlSecTransformContextStringRead_object_exceeds_max(&mldsaParams);
        test_xmlSecTransformContextStringRead_both_method_and_object(&mldsaParams);
        test_xmlSecTransformContextStringRead_non_empty_buffer(&mldsaParams);

        if(testGroupFinished() != 1) { success = 0; }
    }
#endif /* XMLSEC_NO_MLDSA */

#ifndef XMLSEC_NO_SLHDSA
    {
        const xmlSecUnitTestContextStringParams slhdsaParams = {
            "SLH-DSA",
            "http://www.w3.org/2026/08/xmldsig-more#slh-dsa-sha2-128s",
            XMLSEC_SLHDSA_MAX_SIZE,
            xmlSecTransformSLHDSAReadContextString
        };

        testGroupStart("xmlSecTransformSLHDSAReadContextString");

        test_xmlSecTransformContextStringRead_null_node(&slhdsaParams);
        test_xmlSecTransformContextStringRead_null_buffer(&slhdsaParams);
        test_xmlSecTransformContextStringRead_no_context(&slhdsaParams);
        test_xmlSecTransformContextStringRead_signature_method(&slhdsaParams);
        test_xmlSecTransformContextStringRead_signature_method_max_size(&slhdsaParams);
        test_xmlSecTransformContextStringRead_signature_method_exceeds_max(&slhdsaParams);
        test_xmlSecTransformContextStringRead_invalid_base64(&slhdsaParams);
        test_xmlSecTransformContextStringRead_unexpected_first_child(&slhdsaParams);
        test_xmlSecTransformContextStringRead_extra_child_after_context(&slhdsaParams);
        test_xmlSecTransformContextStringRead_wrong_namespace(&slhdsaParams);
        test_xmlSecTransformContextStringRead_object(&slhdsaParams);
        test_xmlSecTransformContextStringRead_object_exceeds_max(&slhdsaParams);
        test_xmlSecTransformContextStringRead_both_method_and_object(&slhdsaParams);
        test_xmlSecTransformContextStringRead_non_empty_buffer(&slhdsaParams);

        if(testGroupFinished() != 1) { success = 0; }
    }
#endif /* XMLSEC_NO_SLHDSA */

#ifndef XMLSEC_NO_EDDSA
    {
        const xmlSecUnitTestContextStringParams eddsaParams = {
            "EdDSA",
            "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519ctx",
            XMLSEC_EDDSA_MAX_SIZE,
            xmlSecTransformEdDSAReadContextString
        };

        testGroupStart("xmlSecTransformEdDSAReadContextString");

        test_xmlSecTransformContextStringRead_null_node(&eddsaParams);
        test_xmlSecTransformContextStringRead_null_buffer(&eddsaParams);
        test_xmlSecTransformContextStringRead_no_context(&eddsaParams);
        test_xmlSecTransformContextStringRead_signature_method(&eddsaParams);
        test_xmlSecTransformContextStringRead_signature_method_max_size(&eddsaParams);
        test_xmlSecTransformContextStringRead_signature_method_exceeds_max(&eddsaParams);
        test_xmlSecTransformContextStringRead_invalid_base64(&eddsaParams);
        test_xmlSecTransformContextStringRead_unexpected_first_child(&eddsaParams);
        test_xmlSecTransformContextStringRead_extra_child_after_context(&eddsaParams);
        test_xmlSecTransformContextStringRead_wrong_namespace(&eddsaParams);
        test_xmlSecTransformContextStringRead_object(&eddsaParams);
        test_xmlSecTransformContextStringRead_object_exceeds_max(&eddsaParams);
        test_xmlSecTransformContextStringRead_both_method_and_object(&eddsaParams);
        test_xmlSecTransformContextStringRead_non_empty_buffer(&eddsaParams);

        if(testGroupFinished() != 1) { success = 0; }
    }
#endif /* XMLSEC_NO_EDDSA */
#endif /* !XMLSEC_NO_MLDSA || !XMLSEC_NO_SLHDSA || !XMLSEC_NO_EDDSA */

    return(success);
}
