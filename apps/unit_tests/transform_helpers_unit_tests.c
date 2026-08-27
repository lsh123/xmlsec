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
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "xmlsec_unit_tests.h"
#include <xmlsec/strings.h>
#include <xmlsec/xmltree.h>
#include "../../src/transform_helpers.h"

#ifndef XMLSEC_NO_CHACHA20

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

static xmlNodePtr
xmlSecUnitTestFindChild(xmlNodePtr node, const xmlChar* name) {
    xmlNodePtr cur;

    xmlSecAssert2(node != NULL, NULL);
    xmlSecAssert2(name != NULL, NULL);

    for(cur = xmlSecGetNextElementNode(node->children); cur != NULL; cur = xmlSecGetNextElementNode(cur->next)) {
        if(xmlSecCheckNodeName(cur, name, xmlSecXmldsig2021MoreNs)) {
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
    if((ret < 0) || (ivSize != XMLSEC_CHACHA20_IV_SIZE) || (memcmp(ivRoundTrip, iv, sizeof(iv)) != 0)) {
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

    return(success);
}
