/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * xmltree unit tests
 *
 * See Copyright for the status of this software.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#include <stdlib.h>
#include <string.h>

#include <libxml/tree.h>

/* must be included before any other xmlsec header */
#include "xmlsec_unit_tests.h"
#include <xmlsec/xmltree.h>
#include <xmlsec/buffer.h>
#include <xmlsec/strings.h>

#define TEST_NS BAD_CAST "http://test.ns"

/*************************************************************************
 * helpers
 *************************************************************************/
static xmlDocPtr
xmltreeTestCreateDoc(const xmlChar* rootName, const xmlChar* rootNs) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNsPtr ns;

    doc = xmlNewDoc(BAD_CAST "1.0");
    if(doc == NULL) { return(NULL); }

    root = xmlNewDocNode(doc, NULL, rootName, NULL);
    if(root == NULL) { xmlFreeDoc(doc); return(NULL); }

    xmlDocSetRootElement(doc, root);

    if(rootNs != NULL) {
        ns = xmlNewNs(root, rootNs, NULL);
        if(ns == NULL) { xmlFreeDoc(doc); return(NULL); }
        xmlSetNs(root, ns);
    }
    return(doc);
}

/*************************************************************************
 * xmlSecIsEmptyString
 *************************************************************************/
static void
test_xmlSecIsEmptyString_empty(void) {
    testStart("xmlSecIsEmptyString: empty string");
    if(xmlSecIsEmptyString(BAD_CAST "") != 1) {
        testLog("Error: empty string was not detected as empty\n");
        testFinishedFailure();
        return;
    }
    testFinishedSuccess();
}

static void
test_xmlSecIsEmptyString_whitespace_only(void) {
    testStart("xmlSecIsEmptyString: whitespace-only string");
    if(xmlSecIsEmptyString(BAD_CAST "   \t\n\r") != 1) {
        testLog("Error: whitespace-only string was not detected as empty\n");
        testFinishedFailure();
        return;
    }
    testFinishedSuccess();
}

static void
test_xmlSecIsEmptyString_nonempty(void) {
    testStart("xmlSecIsEmptyString: non-empty string");
    if(xmlSecIsEmptyString(BAD_CAST "hello") != 0) {
        testLog("Error: non-empty string was detected as empty\n");
        testFinishedFailure();
        return;
    }
    testFinishedSuccess();
}

static void
test_xmlSecIsEmptyString_mixed_whitespace(void) {
    testStart("xmlSecIsEmptyString: string with embedded text");
    if(xmlSecIsEmptyString(BAD_CAST " \t hello \t ") != 0) {
        testLog("Error: string with text was detected as empty\n");
        testFinishedFailure();
        return;
    }
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecGetNodeContentAndTrim
 *************************************************************************/
static void
test_xmlSecGetNodeContentAndTrim_plain(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlChar* content;

    testStart("xmlSecGetNodeContentAndTrim: plain content");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    xmlNodeSetContent(root, BAD_CAST "hello");

    content = xmlSecGetNodeContentAndTrim(root);
    if(content == NULL || xmlStrcmp(content, BAD_CAST "hello") != 0) {
        testLog("Error: expected 'hello', got '%s'\n", content ? (char*)content : "NULL");
        xmlFree(content);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFree(content);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecGetNodeContentAndTrim_leading_trailing_spaces(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlChar* content;

    testStart("xmlSecGetNodeContentAndTrim: leading/trailing spaces trimmed");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    xmlNodeSetContent(root, BAD_CAST "   hello world   ");

    content = xmlSecGetNodeContentAndTrim(root);
    if(content == NULL || xmlStrcmp(content, BAD_CAST "hello world") != 0) {
        testLog("Error: expected 'hello world', got '%s'\n", content ? (char*)content : "NULL");
        xmlFree(content);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFree(content);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecGetNodeContentAndTrim_tabs_and_newlines(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlChar* content;

    testStart("xmlSecGetNodeContentAndTrim: tabs and newlines trimmed");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    xmlNodeSetContent(root, BAD_CAST "\t\n  value  \n\t");

    content = xmlSecGetNodeContentAndTrim(root);
    if(content == NULL || xmlStrcmp(content, BAD_CAST "value") != 0) {
        testLog("Error: expected 'value', got '%s'\n", content ? (char*)content : "NULL");
        xmlFree(content);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFree(content);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecGetNodeContentAndTrim_whitespace_only_becomes_empty(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlChar* content;

    testStart("xmlSecGetNodeContentAndTrim: whitespace-only content returns empty string");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    xmlNodeSetContent(root, BAD_CAST "   \t ");

    content = xmlSecGetNodeContentAndTrim(root);
    /* whitespace-only input → trimmed to empty string "" (not NULL) */
    if(content == NULL || xmlStrcmp(content, BAD_CAST "") != 0) {
        testLog("Error: expected empty string, got '%s'\n", content ? (char*)content : "NULL");
        xmlFree(content);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFree(content);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecGetNodeContentAsSize
 *************************************************************************/
static void
test_xmlSecGetNodeContentAsSize_valid(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlSecSize val = 0;
    int ret;

    testStart("xmlSecGetNodeContentAsSize: valid number");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    xmlNodeSetContent(root, BAD_CAST "42");

    ret = xmlSecGetNodeContentAsSize(root, 0, &val);
    if(ret < 0 || val != 42) {
        testLog("Error: expected val=42, got ret=%d val=%u\n", ret, (unsigned int)val);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecGetNodeContentAsSize_with_spaces(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlSecSize val = 0;
    int ret;

    testStart("xmlSecGetNodeContentAsSize: number with surrounding spaces");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    xmlNodeSetContent(root, BAD_CAST "  128  ");

    ret = xmlSecGetNodeContentAsSize(root, 0, &val);
    if(ret < 0 || val != 128) {
        testLog("Error: expected val=128, got ret=%d val=%u\n", ret, (unsigned int)val);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecGetNodeContentAsSize_zero(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlSecSize val = 99;
    int ret;

    testStart("xmlSecGetNodeContentAsSize: zero value");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    xmlNodeSetContent(root, BAD_CAST "0");

    ret = xmlSecGetNodeContentAsSize(root, 99, &val);
    if(ret < 0 || val != 0) {
        testLog("Error: expected val=0, got ret=%d val=%u\n", ret, (unsigned int)val);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecGetNodeContentAsSize_negative_fails(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlSecSize val = 0;
    int ret;

    testStart("xmlSecGetNodeContentAsSize: negative number fails");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    xmlNodeSetContent(root, BAD_CAST "-5");

    ret = xmlSecGetNodeContentAsSize(root, 0, &val);
    if(ret >= 0) {
        testLog("Error: expected failure for negative number, got ret=%d\n", ret);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecGetNodeContentAsSize_nonnumeric_fails(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlSecSize val = 0;
    int ret;

    testStart("xmlSecGetNodeContentAsSize: non-numeric content fails");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    xmlNodeSetContent(root, BAD_CAST "abc");

    ret = xmlSecGetNodeContentAsSize(root, 0, &val);
    if(ret >= 0) {
        testLog("Error: expected failure for non-numeric content, got ret=%d\n", ret);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecGetNodeContentAsHex / xmlSecSetNodeContentAsHex
 *************************************************************************/
static void
test_xmlSecNodeContentHex_roundtrip(void) {
    static const xmlSecByte data[] = { 0x00, 0x11, 0xAB, 0xCD, 0xEF, 0xFF };
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlSecBuffer buf;
    const xmlSecByte* bufData;
    xmlSecSize bufSize;
    int ret;

    testStart("xmlSecSetNodeContentAsHex/xmlSecGetNodeContentAsHex: roundtrip");

    ret = xmlSecBufferInitialize(&buf, 64);
    if(ret < 0) {
        testLog("Error: failed to initialize buffer\n");
        testFinishedFailure();
        return;
    }

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);

    ret = xmlSecSetNodeContentAsHex(root, data, sizeof(data));
    if(ret < 0) {
        testLog("Error: xmlSecSetNodeContentAsHex failed\n");
        xmlFreeDoc(doc);
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }

    ret = xmlSecGetNodeContentAsHex(root, &buf);
    if(ret < 0) {
        testLog("Error: xmlSecGetNodeContentAsHex failed\n");
        xmlFreeDoc(doc);
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }

    bufData = xmlSecBufferGetData(&buf);
    bufSize = xmlSecBufferGetSize(&buf);
    if(bufSize != sizeof(data) || bufData == NULL ||
       memcmp(bufData, data, sizeof(data)) != 0) {
        testLog("Error: hex roundtrip data mismatch (size=%u, expected=%u)\n",
                (unsigned int)bufSize, (unsigned int)sizeof(data));
        xmlFreeDoc(doc);
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
}

static void
test_xmlSecSetNodeContentAsHex_encoding(void) {
    static const xmlSecByte data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    static const char expected[] = "deadbeef";
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlChar* content;
    int ret;

    testStart("xmlSecSetNodeContentAsHex: correct lowercase hex encoding");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);

    ret = xmlSecSetNodeContentAsHex(root, data, sizeof(data));
    if(ret < 0) {
        testLog("Error: xmlSecSetNodeContentAsHex failed\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    content = xmlNodeGetContent(root);
    if(content == NULL || xmlStrcmp(content, BAD_CAST expected) != 0) {
        testLog("Error: expected '%s', got '%s'\n", expected,
                content ? (char*)content : "NULL");
        xmlFree(content);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFree(content);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecSetNodeContentAsHex_empty(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlChar* content;
    int ret;

    testStart("xmlSecSetNodeContentAsHex: empty data produces empty content");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);

    ret = xmlSecSetNodeContentAsHex(root, BAD_CAST "", 0);
    if(ret < 0) {
        testLog("Error: xmlSecSetNodeContentAsHex failed for empty data\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    content = xmlNodeGetContent(root);
    if(content == NULL || xmlStrcmp(content, BAD_CAST "") != 0) {
        testLog("Error: expected empty string, got '%s'\n",
                content ? (char*)content : "NULL");
        xmlFree(content);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFree(content);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecIsEmptyNode
 *************************************************************************/
static void
test_xmlSecIsEmptyNode_no_children(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    int ret;

    testStart("xmlSecIsEmptyNode: no children");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);

    ret = xmlSecIsEmptyNode(root);
    if(ret != 1) {
        testLog("Error: expected empty (1), got %d\n", ret);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecIsEmptyNode_whitespace_text(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    int ret;

    testStart("xmlSecIsEmptyNode: whitespace-only text child");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    xmlNodeSetContent(root, BAD_CAST "   \n\t  ");

    ret = xmlSecIsEmptyNode(root);
    if(ret != 1) {
        testLog("Error: expected empty (1) for whitespace-only node, got %d\n", ret);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecIsEmptyNode_text_content(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    int ret;

    testStart("xmlSecIsEmptyNode: non-empty text content");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    xmlNodeSetContent(root, BAD_CAST "hello");

    ret = xmlSecIsEmptyNode(root);
    if(ret != 0) {
        testLog("Error: expected non-empty (0), got %d\n", ret);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecIsEmptyNode_child_element(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    int ret;

    testStart("xmlSecIsEmptyNode: child element makes node non-empty");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    if(xmlNewChild(root, NULL, BAD_CAST "Child", NULL) == NULL) {
        testLog("Error: failed to add child element\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = xmlSecIsEmptyNode(root);
    if(ret != 0) {
        testLog("Error: expected non-empty (0) for node with element child, got %d\n", ret);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecCreateTree
 *************************************************************************/
static void
test_xmlSecCreateTree_with_ns(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    const xmlChar* nsHref;

    testStart("xmlSecCreateTree: creates tree with correct root name and namespace");

    doc = xmlSecCreateTree(BAD_CAST "TestRoot", BAD_CAST "http://test.example.com/ns");
    if(doc == NULL) {
        testLog("Error: xmlSecCreateTree returned NULL\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    if(root == NULL) {
        testLog("Error: no root element\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    if(xmlStrcmp(root->name, BAD_CAST "TestRoot") != 0) {
        testLog("Error: expected root name 'TestRoot', got '%s'\n", (char*)root->name);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    nsHref = xmlSecGetNodeNsHref(root);
    if(nsHref == NULL || xmlStrcmp(nsHref, BAD_CAST "http://test.example.com/ns") != 0) {
        testLog("Error: expected ns 'http://test.example.com/ns', got '%s'\n",
                nsHref ? (char*)nsHref : "NULL");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecCreateTree_null_ns(void) {
    xmlDocPtr doc;
    xmlNodePtr root;

    testStart("xmlSecCreateTree: creates tree with NULL namespace");

    doc = xmlSecCreateTree(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: xmlSecCreateTree returned NULL\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    if(root == NULL || xmlStrcmp(root->name, BAD_CAST "Root") != 0) {
        testLog("Error: root element missing or wrong name\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecAddChild
 *************************************************************************/
static void
test_xmlSecAddChild_name_and_ns(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child;
    const xmlChar* nsHref;

    testStart("xmlSecAddChild: child has correct name and namespace");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    child = xmlSecAddChild(root, BAD_CAST "Child", BAD_CAST "http://ns.example.com");
    if(child == NULL) {
        testLog("Error: xmlSecAddChild returned NULL\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    if(xmlStrcmp(child->name, BAD_CAST "Child") != 0) {
        testLog("Error: expected name 'Child', got '%s'\n", (char*)child->name);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    nsHref = xmlSecGetNodeNsHref(child);
    if(nsHref == NULL || xmlStrcmp(nsHref, BAD_CAST "http://ns.example.com") != 0) {
        testLog("Error: expected ns 'http://ns.example.com', got '%s'\n",
                nsHref ? (char*)nsHref : "NULL");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecAddChild_multiple_distinct(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child1, child2;

    testStart("xmlSecAddChild: two calls produce two distinct nodes");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    child1 = xmlSecAddChild(root, BAD_CAST "First",  BAD_CAST "http://ns.example.com");
    child2 = xmlSecAddChild(root, BAD_CAST "Second", BAD_CAST "http://ns.example.com");
    if(child1 == NULL || child2 == NULL || child1 == child2) {
        testLog("Error: expected two distinct children\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecCheckNodeName
 *************************************************************************/
static void
test_xmlSecCheckNodeName_match(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child;

    testStart("xmlSecCheckNodeName: matching name and ns returns 1");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    child = xmlSecAddChild(root, BAD_CAST "Target", TEST_NS);
    if(child == NULL) {
        testLog("Error: failed to add child\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    if(xmlSecCheckNodeName(child, BAD_CAST "Target", TEST_NS) != 1) {
        testLog("Error: expected 1 for matching name and ns\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecCheckNodeName_wrong_name(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child;

    testStart("xmlSecCheckNodeName: wrong name returns 0");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    child = xmlSecAddChild(root, BAD_CAST "Target", TEST_NS);
    if(child == NULL) {
        testLog("Error: failed to add child\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    if(xmlSecCheckNodeName(child, BAD_CAST "Other", TEST_NS) != 0) {
        testLog("Error: expected 0 for wrong name\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecCheckNodeName_wrong_ns(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child;

    testStart("xmlSecCheckNodeName: wrong namespace returns 0");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    child = xmlSecAddChild(root, BAD_CAST "Target", TEST_NS);
    if(child == NULL) {
        testLog("Error: failed to add child\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    if(xmlSecCheckNodeName(child, BAD_CAST "Target", BAD_CAST "http://other.ns") != 0) {
        testLog("Error: expected 0 for wrong namespace\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecFindChild
 *************************************************************************/
static void
test_xmlSecFindChild_found(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child, found;

    testStart("xmlSecFindChild: finds existing child");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    child = xmlSecAddChild(root, BAD_CAST "Child", TEST_NS);
    if(child == NULL) {
        testLog("Error: failed to add child\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    found = xmlSecFindChild(root, BAD_CAST "Child", TEST_NS);
    if(found == NULL || found != child) {
        testLog("Error: xmlSecFindChild did not return the expected node\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecFindChild_not_found(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr found;

    testStart("xmlSecFindChild: returns NULL when child not found");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);

    found = xmlSecFindChild(root, BAD_CAST "Missing", TEST_NS);
    if(found != NULL) {
        testLog("Error: expected NULL for missing child\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecFindChild_first_of_two(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child1, child2, found;

    testStart("xmlSecFindChild: returns first matching child when multiple exist");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    child1 = xmlSecAddChild(root, BAD_CAST "Child", TEST_NS);
    child2 = xmlSecAddChild(root, BAD_CAST "Child", TEST_NS);
    if(child1 == NULL || child2 == NULL) {
        testLog("Error: failed to add children\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    found = xmlSecFindChild(root, BAD_CAST "Child", TEST_NS);
    if(found != child1) {
        testLog("Error: expected first child to be returned\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecFindSibling
 *************************************************************************/
static void
test_xmlSecFindSibling_finds_next(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child1, child2, found;

    testStart("xmlSecFindSibling: finds next sibling by name and ns");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    child1 = xmlSecAddChild(root, BAD_CAST "First",  TEST_NS);
    child2 = xmlSecAddChild(root, BAD_CAST "Second", TEST_NS);
    if(child1 == NULL || child2 == NULL) {
        testLog("Error: failed to add children\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    found = xmlSecFindSibling(child1, BAD_CAST "Second", TEST_NS);
    if(found == NULL || found != child2) {
        testLog("Error: xmlSecFindSibling did not find second child\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecFindSibling_matches_self(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child, found;

    testStart("xmlSecFindSibling: matches self if it satisfies criteria");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    child = xmlSecAddChild(root, BAD_CAST "Only", TEST_NS);
    if(child == NULL) {
        testLog("Error: failed to add child\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    found = xmlSecFindSibling(child, BAD_CAST "Only", TEST_NS);
    if(found != child) {
        testLog("Error: expected self to be returned\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecFindParent
 *************************************************************************/
static void
test_xmlSecFindParent_matches_self(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr found;

    testStart("xmlSecFindParent: returns self when cur matches");

    doc = xmlSecCreateTree(BAD_CAST "Root", TEST_NS);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);

    found = xmlSecFindParent(root, BAD_CAST "Root", TEST_NS);
    if(found != root) {
        testLog("Error: expected self, got different node\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecFindParent_finds_ancestor(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr middle, leaf;
    xmlNodePtr found;

    testStart("xmlSecFindParent: finds ancestor by walking up tree");

    doc = xmlSecCreateTree(BAD_CAST "Root", TEST_NS);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    middle = xmlSecAddChild(root,   BAD_CAST "Middle", TEST_NS);
    leaf   = xmlSecAddChild(middle, BAD_CAST "Leaf",   TEST_NS);
    if(middle == NULL || leaf == NULL) {
        testLog("Error: failed to add nodes\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    found = xmlSecFindParent(leaf, BAD_CAST "Root", TEST_NS);
    if(found != root) {
        testLog("Error: expected root ancestor\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecFindParent_not_found(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child;
    xmlNodePtr found;

    testStart("xmlSecFindParent: returns NULL when no match found");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    child = xmlSecAddChild(root, BAD_CAST "Child", TEST_NS);
    if(child == NULL) {
        testLog("Error: failed to add child\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    found = xmlSecFindParent(child, BAD_CAST "Missing", TEST_NS);
    if(found != NULL) {
        testLog("Error: expected NULL for non-existent ancestor\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecFindNode
 *************************************************************************/
static void
test_xmlSecFindNode_direct_child(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child, found;

    testStart("xmlSecFindNode: finds direct child");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    child = xmlSecAddChild(root, BAD_CAST "Target", TEST_NS);
    if(child == NULL) {
        testLog("Error: failed to add child\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    found = xmlSecFindNode(root, BAD_CAST "Target", TEST_NS);
    if(found != child) {
        testLog("Error: xmlSecFindNode did not find direct child\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecFindNode_nested_child(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr parent, target, found;

    testStart("xmlSecFindNode: finds deeply nested node");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    parent = xmlSecAddChild(root,   BAD_CAST "Parent",   TEST_NS);
    target = xmlSecAddChild(parent, BAD_CAST "DeepNode", TEST_NS);
    if(parent == NULL || target == NULL) {
        testLog("Error: failed to add nodes\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    found = xmlSecFindNode(root, BAD_CAST "DeepNode", TEST_NS);
    if(found != target) {
        testLog("Error: xmlSecFindNode did not find nested node\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecFindNode_not_found(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr found;

    testStart("xmlSecFindNode: returns NULL when node not found");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);

    found = xmlSecFindNode(root, BAD_CAST "Missing", TEST_NS);
    if(found != NULL) {
        testLog("Error: expected NULL\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecGetNextElementNode
 *************************************************************************/
static void
test_xmlSecGetNextElementNode_already_element(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr elem, found;

    testStart("xmlSecGetNextElementNode: returns self when already an element");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);
    elem = xmlSecAddChild(root, BAD_CAST "Elem", TEST_NS);
    if(elem == NULL) {
        testLog("Error: failed to add child\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    found = xmlSecGetNextElementNode(elem);
    if(found != elem) {
        testLog("Error: expected same element node, got different node\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecGetNextElementNode_skips_text(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr textNode, elemNode, found;

    testStart("xmlSecGetNextElementNode: skips text node to find element");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);

    /* build: <Root>sometext<Elem/></Root> */
    textNode = xmlNewText(BAD_CAST "some text");
    if(textNode == NULL) {
        testLog("Error: failed to create text node\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlAddChild(root, textNode);

    elemNode = xmlNewChild(root, NULL, BAD_CAST "Elem", NULL);
    if(elemNode == NULL) {
        testLog("Error: failed to add element node\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    found = xmlSecGetNextElementNode(textNode);
    if(found != elemNode) {
        testLog("Error: expected element node after text, got unexpected node\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecGetNextElementNode_no_elements(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr textNode, found;

    testStart("xmlSecGetNextElementNode: returns NULL when no element follows");

    doc = xmltreeTestCreateDoc(BAD_CAST "Root", NULL);
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);

    textNode = xmlNewText(BAD_CAST "only text");
    if(textNode == NULL) {
        testLog("Error: failed to create text node\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlAddChild(root, textNode);

    found = xmlSecGetNextElementNode(textNode);
    if(found != NULL) {
        testLog("Error: expected NULL when no element follows text\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

/*************************************************************************
 * exported entry point
 *************************************************************************/
int
test_xmltree(void) {
    int success = 1;

    testGroupStart("xmlSecIsEmptyString");
    test_xmlSecIsEmptyString_empty();
    test_xmlSecIsEmptyString_whitespace_only();
    test_xmlSecIsEmptyString_nonempty();
    test_xmlSecIsEmptyString_mixed_whitespace();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecGetNodeContentAndTrim");
    test_xmlSecGetNodeContentAndTrim_plain();
    test_xmlSecGetNodeContentAndTrim_leading_trailing_spaces();
    test_xmlSecGetNodeContentAndTrim_tabs_and_newlines();
    test_xmlSecGetNodeContentAndTrim_whitespace_only_becomes_empty();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecGetNodeContentAsSize");
    test_xmlSecGetNodeContentAsSize_valid();
    test_xmlSecGetNodeContentAsSize_with_spaces();
    test_xmlSecGetNodeContentAsSize_zero();
    test_xmlSecGetNodeContentAsSize_negative_fails();
    test_xmlSecGetNodeContentAsSize_nonnumeric_fails();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecNodeContentHex");
    test_xmlSecNodeContentHex_roundtrip();
    test_xmlSecSetNodeContentAsHex_encoding();
    test_xmlSecSetNodeContentAsHex_empty();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecIsEmptyNode");
    test_xmlSecIsEmptyNode_no_children();
    test_xmlSecIsEmptyNode_whitespace_text();
    test_xmlSecIsEmptyNode_text_content();
    test_xmlSecIsEmptyNode_child_element();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecCreateTree");
    test_xmlSecCreateTree_with_ns();
    test_xmlSecCreateTree_null_ns();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecAddChild");
    test_xmlSecAddChild_name_and_ns();
    test_xmlSecAddChild_multiple_distinct();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecCheckNodeName");
    test_xmlSecCheckNodeName_match();
    test_xmlSecCheckNodeName_wrong_name();
    test_xmlSecCheckNodeName_wrong_ns();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecFindChild");
    test_xmlSecFindChild_found();
    test_xmlSecFindChild_not_found();
    test_xmlSecFindChild_first_of_two();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecFindSibling");
    test_xmlSecFindSibling_finds_next();
    test_xmlSecFindSibling_matches_self();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecFindParent");
    test_xmlSecFindParent_matches_self();
    test_xmlSecFindParent_finds_ancestor();
    test_xmlSecFindParent_not_found();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecFindNode");
    test_xmlSecFindNode_direct_child();
    test_xmlSecFindNode_nested_child();
    test_xmlSecFindNode_not_found();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecGetNextElementNode");
    test_xmlSecGetNextElementNode_already_element();
    test_xmlSecGetNextElementNode_skips_text();
    test_xmlSecGetNextElementNode_no_elements();
    if(testGroupFinished() != 1) { success = 0; }

    return(success);
}
