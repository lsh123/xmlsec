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
#include <libxml/xpathInternals.h>

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
    childAttr = (child != NULL) ? child->properties : NULL;
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

static void
test_xmlSecNodeSetDumpTextNodes_preserves_document_order(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlSecNodeSetPtr nset;
    xmlBufferPtr buffer;
    xmlOutputBufferPtr out;
    int ret;

    testStart("xmlSecNodeSetDumpTextNodes preserves document order");

    doc = nodesetTestParseDoc("<Root><A>1</A><B>2</B><C><D>3</D></C></Root>");
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }

    root = xmlDocGetRootElement(doc);
    nset = xmlSecNodeSetGetChildren(doc, root, 1, 0);
    buffer = xmlBufferCreate();
    out = (buffer != NULL) ? xmlOutputBufferCreateBuffer(buffer, NULL) : NULL;
    if((root == NULL) || (nset == NULL) || (buffer == NULL) || (out == NULL)) {
        testLog("Error: failed to prepare dump text nodes test data\n");
        if(out != NULL) {
            (void)xmlOutputBufferClose(out);
        } else if(buffer != NULL) {
            xmlBufferFree(buffer);
        }
        xmlSecNodeSetDestroy(nset);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = xmlSecNodeSetDumpTextNodes(nset, out);
    if((ret < 0) || (xmlOutputBufferFlush(out) < 0) ||
       !xmlStrEqual(xmlBufferContent(buffer), BAD_CAST "123")) {
        testLog("Error: dump text nodes output mismatch (ret=%d, text='%s')\n",
            ret, (xmlBufferContent(buffer) != NULL) ? (const char*)xmlBufferContent(buffer) : "(null)");
        xmlOutputBufferClose(out);
        xmlSecNodeSetDestroy(nset);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlOutputBufferClose(out);
    xmlSecNodeSetDestroy(nset);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecNodeSetWalk_deduplicates_overlapping_subtrees(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child;
    xmlNodeSetPtr nodes;
    xmlSecNodeSetPtr nset;
    struct nodesetWalkStats stats;
    int ret;

    testStart("xmlSecNodeSetWalk visits each node once for overlapping subtrees");

    doc = nodesetTestParseDoc("<Root><Child>text</Child></Root>");
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }

    root = xmlDocGetRootElement(doc);
    child = nodesetTestFindChild(root, BAD_CAST "Child");
    if((root == NULL) || (child == NULL)) {
        testLog("Error: failed to prepare walk dedup test data\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    /* build a Tree node set whose list contains both an ancestor and a
     * descendant so that the walked subtrees overlap */
    nodes = xmlXPathNodeSetCreate(root);
    if(nodes == NULL) {
        testLog("Error: failed to create XPath node set\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    if(xmlXPathNodeSetAdd(nodes, child) < 0) {
        testLog("Error: failed to add descendant to XPath node set\n");
        xmlXPathFreeNodeSet(nodes);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    nset = xmlSecNodeSetCreate(doc, nodes, xmlSecNodeSetTree);
    if(nset == NULL) {
        testLog("Error: failed to create xmlsec node set\n");
        xmlXPathFreeNodeSet(nodes);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    memset(&stats, 0, sizeof(stats));
    ret = xmlSecNodeSetWalk(nset, nodesetTestWalkStatsCallback, &stats);
    if((ret < 0) || (stats.total != 3) || (stats.elements != 2) || (stats.text != 1)) {
        testLog("Error: walk visited overlapping nodes more than once "
            "(ret=%d total=%d elem=%d text=%d)\n",
            ret, stats.total, stats.elements, stats.text);
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
test_xmlSecNodeSetWalk_normal_set_visits_each_node_once(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child;
    xmlNodeSetPtr nodes;
    xmlSecNodeSetPtr nset;
    struct nodesetWalkStats stats;
    int ret;

    testStart("xmlSecNodeSetWalk visits each node once for a Normal set with overlapping members");

    doc = nodesetTestParseDoc("<Root><Child>text</Child></Root>");
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }

    root = xmlDocGetRootElement(doc);
    child = nodesetTestFindChild(root, BAD_CAST "Child");
    if((root == NULL) || (child == NULL)) {
        testLog("Error: failed to prepare walk dedup test data\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    /* a Normal node set containing both an ancestor and a descendant */
    nodes = xmlXPathNodeSetCreate(root);
    if(nodes == NULL) {
        testLog("Error: failed to create XPath node set\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    if(xmlXPathNodeSetAdd(nodes, child) < 0) {
        testLog("Error: failed to add descendant to XPath node set\n");
        xmlXPathFreeNodeSet(nodes);
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

    /* only the set members are visited (text is not in the set), and each
     * of them must be visited exactly once */
    memset(&stats, 0, sizeof(stats));
    ret = xmlSecNodeSetWalk(nset, nodesetTestWalkStatsCallback, &stats);
    if((ret < 0) || (stats.total != 2) || (stats.elements != 2) || (stats.text != 0)) {
        testLog("Error: walk visited overlapping nodes more than once "
            "(ret=%d total=%d elem=%d text=%d)\n",
            ret, stats.total, stats.elements, stats.text);
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
test_xmlSecNodeSetWalk_skips_descendants_listed_before_ancestors(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr child;
    xmlNodeSetPtr nodes;
    xmlSecNodeSetPtr nset;
    struct nodesetWalkStats stats;
    int ret;

    testStart("xmlSecNodeSetWalk visits each node once when the descendant is listed first");

    doc = nodesetTestParseDoc("<Root><Child>text</Child></Root>");
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }

    root = xmlDocGetRootElement(doc);
    child = nodesetTestFindChild(root, BAD_CAST "Child");
    if((root == NULL) || (child == NULL)) {
        testLog("Error: failed to prepare walk dedup test data\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    /* add the descendant first so that it appears before its ancestor in
     * the node list */
    nodes = xmlXPathNodeSetCreate(child);
    if(nodes == NULL) {
        testLog("Error: failed to create XPath node set\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    if(xmlXPathNodeSetAdd(nodes, root) < 0) {
        testLog("Error: failed to add ancestor to XPath node set\n");
        xmlXPathFreeNodeSet(nodes);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    nset = xmlSecNodeSetCreate(doc, nodes, xmlSecNodeSetTree);
    if(nset == NULL) {
        testLog("Error: failed to create xmlsec node set\n");
        xmlXPathFreeNodeSet(nodes);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    /* each node of the covered subtree must be visited exactly once */
    memset(&stats, 0, sizeof(stats));
    ret = xmlSecNodeSetWalk(nset, nodesetTestWalkStatsCallback, &stats);
    if((ret < 0) || (stats.total != 3) || (stats.elements != 2) || (stats.text != 1)) {
        testLog("Error: walk visited overlapping nodes more than once "
            "(ret=%d total=%d elem=%d text=%d)\n",
            ret, stats.total, stats.elements, stats.text);
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
test_xmlSecNodeSetWalk_visits_nested_chain_once(void) {
    xmlDocPtr doc;
    xmlNodePtr a;
    xmlNodePtr b;
    xmlNodePtr c;
    xmlNodeSetPtr nodes;
    xmlSecNodeSetPtr nset;
    struct nodesetWalkStats stats;
    int ret;

    testStart("xmlSecNodeSetWalk visits each node once for a fully nested chain");

    doc = nodesetTestParseDoc("<A><B><C>text</C></B></A>");
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }

    a = xmlDocGetRootElement(doc);
    b = nodesetTestFindChild(a, BAD_CAST "B");
    c = (b != NULL) ? nodesetTestFindChild(b, BAD_CAST "C") : NULL;
    if((a == NULL) || (b == NULL) || (c == NULL)) {
        testLog("Error: failed to prepare walk dedup test data\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    /* a Tree node set containing three nested levels */
    nodes = xmlXPathNodeSetCreate(a);
    if(nodes == NULL) {
        testLog("Error: failed to create XPath node set\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    if((xmlXPathNodeSetAdd(nodes, b) < 0) || (xmlXPathNodeSetAdd(nodes, c) < 0)) {
        testLog("Error: failed to add nested nodes to XPath node set\n");
        xmlXPathFreeNodeSet(nodes);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    nset = xmlSecNodeSetCreate(doc, nodes, xmlSecNodeSetTree);
    if(nset == NULL) {
        testLog("Error: failed to create xmlsec node set\n");
        xmlXPathFreeNodeSet(nodes);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    /* A, B, C and the text node must each be visited exactly once */
    memset(&stats, 0, sizeof(stats));
    ret = xmlSecNodeSetWalk(nset, nodesetTestWalkStatsCallback, &stats);
    if((ret < 0) || (stats.total != 4) || (stats.elements != 3) || (stats.text != 1)) {
        testLog("Error: walk visited overlapping nodes more than once "
            "(ret=%d total=%d elem=%d text=%d)\n",
            ret, stats.total, stats.elements, stats.text);
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
test_xmlSecNodeSetAdd_union_head_is_absolute_set(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr keep;
    xmlNodePtr drop;
    xmlNodeSetPtr nodes;
    xmlSecNodeSetPtr nset;
    int retKeep;
    int retDrop;

    testStart("xmlSecNodeSetAdd with a Union head treats the set as absolute");

    doc = nodesetTestParseDoc("<Root><Keep/><Drop/></Root>");
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }

    root = xmlDocGetRootElement(doc);
    keep = nodesetTestFindChild(root, BAD_CAST "Keep");
    drop = nodesetTestFindChild(root, BAD_CAST "Drop");
    if((root == NULL) || (keep == NULL) || (drop == NULL)) {
        testLog("Error: failed to prepare union head test data\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    /* a node set that contains only the Keep element */
    nodes = xmlXPathNodeSetCreate(keep);
    if(nodes == NULL) {
        testLog("Error: failed to create XPath node set\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    /* adding with a Union head used to match every node (Union is a no-op
     * against the universal set); it must instead behave as an absolute set */
    nset = xmlSecNodeSetCreate(doc, nodes, xmlSecNodeSetNormal);
    if(nset == NULL) {
        testLog("Error: xmlSecNodeSetCreate failed\n");
        xmlXPathFreeNodeSet(nodes);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    nset = xmlSecNodeSetAdd(NULL, nset, xmlSecNodeSetUnion);
    if(nset == NULL) {
        testLog("Error: xmlSecNodeSetAdd failed for union head\n");
        /* nset owns nodes, so both will be freed by destroy */
        xmlSecNodeSetDestroy(nset);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    retKeep = xmlSecNodeSetContains(nset, keep, root);
    retDrop = xmlSecNodeSetContains(nset, drop, root);
    if((retKeep != 1) || (retDrop != 0)) {
        testLog("Error: union head node set membership is incorrect "
            "(keep=%d drop=%d)\n", retKeep, retDrop);
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
test_xmlSecNodeSetAdd_union_after_intersection_keeps_base_set(void) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr a;
    xmlNodePtr b;
    xmlNodePtr c;
    xmlNodePtr d;
    xmlNodeSetPtr nodesA;
    xmlNodeSetPtr nodesB;
    xmlNodeSetPtr nodesC;
    xmlSecNodeSetPtr nset;
    xmlSecNodeSetPtr tmp;
    int retA;
    int retB;
    int retC;
    int retD;

    testStart("xmlSecNodeSetAdd with a Union after an Intersection keeps the base set");

    doc = nodesetTestParseDoc("<Root><A><B><C/></B></A><D/></Root>");
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }

    root = xmlDocGetRootElement(doc);
    a = nodesetTestFindChild(root, BAD_CAST "A");
    d = nodesetTestFindChild(root, BAD_CAST "D");
    b = (a != NULL) ? nodesetTestFindChild(a, BAD_CAST "B") : NULL;
    c = (b != NULL) ? nodesetTestFindChild(b, BAD_CAST "C") : NULL;
    if((root == NULL) || (a == NULL) || (b == NULL) || (c == NULL) || (d == NULL)) {
        testLog("Error: failed to prepare union-after-intersection test data\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    /* build the list exactly like the xpath2 transform does:
     * intersect A, then subtract B, then union C. Because each new
     * element is inserted before the head, the final list (from the
     * head) is A(Intersection) -> C(Union) -> B(Subtraction) */
    nodesA = xmlXPathNodeSetCreate(a);
    nodesB = xmlXPathNodeSetCreate(b);
    nodesC = xmlXPathNodeSetCreate(c);
    if((nodesA == NULL) || (nodesB == NULL) || (nodesC == NULL)) {
        testLog("Error: failed to create XPath node sets\n");
        if(nodesA != NULL) { xmlXPathFreeNodeSet(nodesA); }
        if(nodesB != NULL) { xmlXPathFreeNodeSet(nodesB); }
        if(nodesC != NULL) { xmlXPathFreeNodeSet(nodesC); }
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    nset = xmlSecNodeSetCreate(doc, nodesA, xmlSecNodeSetNormal);
    if(nset == NULL) {
        testLog("Error: xmlSecNodeSetCreate failed\n");
        xmlXPathFreeNodeSet(nodesA);
        xmlXPathFreeNodeSet(nodesB);
        xmlXPathFreeNodeSet(nodesC);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    tmp = xmlSecNodeSetCreate(doc, nodesB, xmlSecNodeSetNormal);
    if(tmp == NULL) {
        testLog("Error: xmlSecNodeSetCreate failed\n");
        xmlXPathFreeNodeSet(nodesC);
        xmlSecNodeSetDestroy(nset);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    nset = xmlSecNodeSetAdd(nset, tmp, xmlSecNodeSetSubtraction);
    if(nset == NULL) {
        testLog("Error: xmlSecNodeSetAdd failed for subtraction\n");
        xmlXPathFreeNodeSet(nodesC);
        xmlSecNodeSetDestroy(nset);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    tmp = xmlSecNodeSetCreate(doc, nodesC, xmlSecNodeSetNormal);
    if(tmp == NULL) {
        testLog("Error: xmlSecNodeSetCreate failed\n");
        xmlSecNodeSetDestroy(nset);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    nset = xmlSecNodeSetAdd(nset, tmp, xmlSecNodeSetUnion);
    if(nset == NULL) {
        testLog("Error: xmlSecNodeSetAdd failed for union\n");
        xmlSecNodeSetDestroy(nset);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    /* the expected set is (A union C) minus B: A and C are members,
     * B and D are not. A used to be lost because the Union element
     * overwrote the base set established by the Intersection head */
    retA = xmlSecNodeSetContains(nset, a, root);
    retB = xmlSecNodeSetContains(nset, b, a);
    retC = xmlSecNodeSetContains(nset, c, b);
    retD = xmlSecNodeSetContains(nset, d, root);
    if((retA != 1) || (retB != 0) || (retC != 1) || (retD != 0)) {
        testLog("Error: union-after-intersection membership is incorrect "
            "(a=%d b=%d c=%d d=%d)\n", retA, retB, retC, retD);
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
    test_xmlSecNodeSetAdd_union_head_is_absolute_set();
    test_xmlSecNodeSetAdd_union_after_intersection_keeps_base_set();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecNodeSetWalk");
    test_xmlSecNodeSetWalk_visits_elements_attributes_and_namespaces();
    test_xmlSecNodeSetDumpTextNodes_preserves_document_order();
    test_xmlSecNodeSetWalk_deduplicates_overlapping_subtrees();
    test_xmlSecNodeSetWalk_normal_set_visits_each_node_once();
    test_xmlSecNodeSetWalk_skips_descendants_listed_before_ancestors();
    test_xmlSecNodeSetWalk_visits_nested_chain_once();
    if(testGroupFinished() != 1) { success = 0; }

    return(success);
}
