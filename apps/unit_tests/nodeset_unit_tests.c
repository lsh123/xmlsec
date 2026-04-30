/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief XML Security Library unit nodeset tests.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlIO.h>

/* must be included before any other xmlsec header */
#include "xmlsec_unit_tests.h"
#include <xmlsec/nodeset.h>

static xmlDocPtr
nodesetTestParseDoc(const char* xml) {
    xmlDocPtr doc;

    xmlSecAssert2(xml != NULL, NULL);

    doc = xmlReadMemory(xml, (int)strlen(xml), "nodeset-test.xml", NULL,
        XML_PARSE_NONET);
    if(doc == NULL) {
        testLog("Error: failed to parse XML\n");
        return(NULL);
    }
    return(doc);
}

static xmlNodePtr
nodesetTestFindChild(xmlNodePtr parent, const xmlChar* name) {
    xmlNodePtr cur;

    xmlSecAssert2(parent != NULL, NULL);
    xmlSecAssert2(name != NULL, NULL);

    for(cur = parent->children; cur != NULL; cur = cur->next) {
        if((cur->type == XML_ELEMENT_NODE) && xmlStrEqual(cur->name, name)) {
            return(cur);
        }
    }
    return(NULL);
}

static xmlNodePtr
nodesetTestFindChildByType(xmlNodePtr parent, xmlElementType type) {
    xmlNodePtr cur;

    xmlSecAssert2(parent != NULL, NULL);

    for(cur = parent->children; cur != NULL; cur = cur->next) {
        if(cur->type == type) {
            return(cur);
        }
    }
    return(NULL);
}

struct nodesetWalkStats {
    int total;
    int elements;
    int attributes;
    int namespaces;
    int text;
};

static int
nodesetTestWalkStatsCallback(xmlSecNodeSetPtr nset,
    xmlNodePtr cur,
    xmlNodePtr parent,
    void* data) {
    struct nodesetWalkStats* stats = (struct nodesetWalkStats*)data;

    (void)nset;
    (void)parent;

    xmlSecAssert2(cur != NULL, -1);
    xmlSecAssert2(stats != NULL, -1);

    ++stats->total;
    switch(cur->type) {
    case XML_ELEMENT_NODE:
        ++stats->elements;
        break;
    case XML_ATTRIBUTE_NODE:
        ++stats->attributes;
        break;
    case XML_NAMESPACE_DECL:
        ++stats->namespaces;
        break;
    case XML_TEXT_NODE:
        ++stats->text;
        break;
    default:
        break;
    }
    return(0);
}

static void
test_xmlSecNodeSetCreate_destroy_doc_destroy(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodeSetPtr nodes;
    xmlSecNodeSetPtr nset;

    testStart("xmlSecNodeSetCreate/xmlSecNodeSetDocDestroy/xmlSecNodeSetDestroy");

    doc = xmlNewDoc(BAD_CAST "1.0");
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }

    root = xmlNewDocNode(doc, NULL, BAD_CAST "Root", NULL);
    if(root == NULL) {
        testLog("Error: failed to create root node\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlDocSetRootElement(doc, root);

    nodes = xmlXPathNodeSetCreate(root);
    if(nodes == NULL) {
        testLog("Error: failed to create XPath node set\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    nset = xmlSecNodeSetCreate(doc, nodes, xmlSecNodeSetNormal);
    if(nset == NULL) {
        testLog("Error: failed to create xmlsec node set\n");
        xmlXPathFreeNodeSet(nodes);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    if((nset->doc != doc) || (nset->nodes != nodes) ||
       (nset->type != xmlSecNodeSetNormal) || (nset->destroyDoc != 0) ||
       (nset->next != nset) || (nset->prev != nset)) {
        testLog("Error: xmlSecNodeSetCreate initialized fields incorrectly\n");
        xmlSecNodeSetDestroy(nset);
        testFinishedFailure();
        return;
    }

    xmlSecNodeSetDocDestroy(nset);
    if(nset->destroyDoc != 1) {
        testLog("Error: xmlSecNodeSetDocDestroy did not set destroyDoc flag\n");
        xmlSecNodeSetDestroy(nset);
        testFinishedFailure();
        return;
    }

    xmlSecNodeSetDestroy(nset);
    testFinishedSuccess();
}

static void
test_xmlSecNodeSetContains_null_nodeset_allows_node(void) {
    xmlDocPtr doc;
    xmlNodePtr root;

    testStart("xmlSecNodeSetContains accepts NULL node set");

    doc = nodesetTestParseDoc("<Root/>");
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }

    root = xmlDocGetRootElement(doc);
    if((root == NULL) || (xmlSecNodeSetContains(NULL, root, root->parent) != 1)) {
        testLog("Error: NULL node set should contain every node\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecNodeSetGetChildren_without_comments_contains_subtree(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child;
    xmlNodePtr grandchild;
    xmlNodePtr sibling;
    xmlNodePtr comment;
    xmlAttrPtr childAttr;
    xmlSecNodeSetPtr nset;

    testStart("xmlSecNodeSetGetChildren without comments contains subtree");

    doc = nodesetTestParseDoc(
        "<Root keep=\"1\"><Child childAttr=\"2\">alpha<!--comment--><Grandchild grandAttr=\"3\"/></Child><Sibling/></Root>");
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }

    root = xmlDocGetRootElement(doc);
    child = nodesetTestFindChild(root, BAD_CAST "Child");
    grandchild = nodesetTestFindChild(child, BAD_CAST "Grandchild");
    sibling = nodesetTestFindChild(root, BAD_CAST "Sibling");
    comment = nodesetTestFindChildByType(child, XML_COMMENT_NODE);
    childAttr = child->properties;
    nset = xmlSecNodeSetGetChildren(doc, child, 0, 0);
    if((child == NULL) || (grandchild == NULL) || (sibling == NULL) ||
       (comment == NULL) || (childAttr == NULL) || (nset == NULL)) {
        testLog("Error: failed to prepare subtree test data\n");
        xmlSecNodeSetDestroy(nset);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    if((xmlSecNodeSetContains(nset, child, root) != 1) ||
       (xmlSecNodeSetContains(nset, grandchild, child) != 1) ||
       (xmlSecNodeSetContains(nset, (xmlNodePtr)childAttr, child) != 1) ||
       (xmlSecNodeSetContains(nset, comment, child) != 0) ||
       (xmlSecNodeSetContains(nset, sibling, root) != 0) ||
       (xmlSecNodeSetContains(nset, root, root->parent) != 0)) {
        testLog("Error: xmlSecNodeSetGetChildren/xmlSecNodeSetContains returned unexpected results\n");
        xmlSecNodeSetDestroy(nset);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecNodeSetDestroy(nset);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecNodeSetGetChildren_invert_excludes_subtree(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child;
    xmlNodePtr grandchild;
    xmlNodePtr sibling;
    xmlSecNodeSetPtr nset;

    testStart("xmlSecNodeSetGetChildren invert excludes subtree");

    doc = nodesetTestParseDoc("<Root><Child><Grandchild/></Child><Sibling/></Root>");
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }

    root = xmlDocGetRootElement(doc);
    child = nodesetTestFindChild(root, BAD_CAST "Child");
    grandchild = nodesetTestFindChild(child, BAD_CAST "Grandchild");
    sibling = nodesetTestFindChild(root, BAD_CAST "Sibling");
    nset = xmlSecNodeSetGetChildren(doc, child, 1, 1);
    if((child == NULL) || (grandchild == NULL) || (sibling == NULL) || (nset == NULL)) {
        testLog("Error: failed to prepare invert test data\n");
        xmlSecNodeSetDestroy(nset);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    if((xmlSecNodeSetContains(nset, root, root->parent) != 1) ||
       (xmlSecNodeSetContains(nset, sibling, root) != 1) ||
       (xmlSecNodeSetContains(nset, child, root) != 0) ||
       (xmlSecNodeSetContains(nset, grandchild, child) != 0)) {
        testLog("Error: inverted node set did not exclude subtree correctly\n");
        xmlSecNodeSetDestroy(nset);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecNodeSetDestroy(nset);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecNodeSetAdd_subtraction_removes_subtree(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr keep;
    xmlNodePtr drop;
    xmlNodePtr nested;
    xmlSecNodeSetPtr nset;
    xmlSecNodeSetPtr removed;

    testStart("xmlSecNodeSetAdd subtraction removes subtree");

    doc = nodesetTestParseDoc("<Root><Keep/><Drop><Nested/></Drop></Root>");
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }

    root = xmlDocGetRootElement(doc);
    keep = nodesetTestFindChild(root, BAD_CAST "Keep");
    drop = nodesetTestFindChild(root, BAD_CAST "Drop");
    nested = nodesetTestFindChild(drop, BAD_CAST "Nested");
    nset = xmlSecNodeSetGetChildren(doc, root, 1, 0);
    removed = xmlSecNodeSetGetChildren(doc, drop, 1, 0);
    if((keep == NULL) || (drop == NULL) || (nested == NULL) ||
       (nset == NULL) || (removed == NULL)) {
        testLog("Error: failed to prepare node set subtraction test\n");
        xmlSecNodeSetDestroy(nset);
        xmlSecNodeSetDestroy(removed);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    if(xmlSecNodeSetAdd(nset, removed, xmlSecNodeSetSubtraction) != nset) {
        testLog("Error: xmlSecNodeSetAdd did not return the original list head\n");
        xmlSecNodeSetDestroy(nset);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    if((xmlSecNodeSetContains(nset, root, root->parent) != 1) ||
       (xmlSecNodeSetContains(nset, keep, root) != 1) ||
       (xmlSecNodeSetContains(nset, drop, root) != 0) ||
       (xmlSecNodeSetContains(nset, nested, drop) != 0)) {
        testLog("Error: subtraction node set membership is incorrect\n");
        xmlSecNodeSetDestroy(nset);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecNodeSetDestroy(nset);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecNodeSetWalk_visits_elements_attributes_and_namespaces(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlSecNodeSetPtr nset;
    struct nodesetWalkStats stats;
    int ret;

    testStart("xmlSecNodeSetWalk visits elements attributes and namespaces");

    memset(&stats, 0, sizeof(stats));
    doc = nodesetTestParseDoc("<p:Root xmlns:p=\"urn:test\" attr=\"1\"/>");
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }

    root = xmlDocGetRootElement(doc);
    nset = xmlSecNodeSetGetChildren(doc, root, 1, 0);
    if((root == NULL) || (nset == NULL)) {
        testLog("Error: failed to prepare walk test data\n");
        xmlSecNodeSetDestroy(nset);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = xmlSecNodeSetWalk(nset, nodesetTestWalkStatsCallback, &stats);
    if((ret < 0) || (stats.total != 3) || (stats.elements != 1) ||
       (stats.attributes != 1) || (stats.namespaces != 1) || (stats.text != 0)) {
        testLog("Error: walk stats mismatch (ret=%d total=%d elem=%d attr=%d ns=%d text=%d)\n",
            ret, stats.total, stats.elements, stats.attributes, stats.namespaces, stats.text);
        xmlSecNodeSetDestroy(nset);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecNodeSetDestroy(nset);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

int
test_nodeset(void) {
    int success = 1;

    testGroupStart("xmlSecNodeSetCreate");
    test_xmlSecNodeSetCreate_destroy_doc_destroy();
    test_xmlSecNodeSetContains_null_nodeset_allows_node();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecNodeSetGetChildren");
    test_xmlSecNodeSetGetChildren_without_comments_contains_subtree();
    test_xmlSecNodeSetGetChildren_invert_excludes_subtree();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecNodeSetAdd");
    test_xmlSecNodeSetAdd_subtraction_removes_subtree();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecNodeSetWalk");
    test_xmlSecNodeSetWalk_visits_elements_attributes_and_namespaces();
    if(testGroupFinished() != 1) { success = 0; }

    return(success);
}