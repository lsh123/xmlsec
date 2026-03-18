/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * transform helpers unit tests
 *
 * See Copyright for the status of this software.
 */
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/debugXML.h>

#include "xmlsec_unit_tests.h"
#include <xmlsec/strings.h>
#include <xmlsec/xmltree.h>
#include "../src/transform_helpers.h"

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
    int noncePresent = 0;
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
test_xmlSecTransformChaCha20ParamsRead_missing_nonce_strict(void) {
    static const char xml[] =
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" "
        "xmlns:dsig-more=\"http://www.w3.org/2021/04/xmldsig-more#\">"
        "<dsig-more:Counter>01020304</dsig-more:Counter>"
        "</EncryptionMethod>";
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlSecByte iv[XMLSEC_CHACHA20_IV_SIZE];
    int noncePresent = 0;
    xmlSecSize ivSize = 0;
    int ret;

    testStart("ChaCha20 read missing nonce strict");

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
        xmlDebugDumpDocument(stdout, doc);

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

#endif /* XMLSEC_NO_CHACHA20 */

int
test_transform_helpers(void) {
#ifndef XMLSEC_NO_CHACHA20
    testGroupStart("transform helpers");

    test_xmlSecTransformChaCha20ParamsRead_missing_nonce();
    test_xmlSecTransformChaCha20ParamsRead_missing_counter();
    test_xmlSecTransformChaCha20ParamsRead_missing_nonce_strict();
    test_xmlSecTransformChaCha20ParamsWrite_roundtrip();
    test_xmlSecTransformChaCha20Poly1305ParamsRead_missing_nonce();
    test_xmlSecTransformChaCha20Poly1305ParamsWrite_roundtrip();

    return(testGroupFinished());
#else
    return(1);
#endif /* XMLSEC_NO_CHACHA20 */
}
