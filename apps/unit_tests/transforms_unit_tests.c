/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief XML Security Library transforms unit tests.
 */
#include <stdio.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "xmlsec_unit_tests.h"
#include <xmlsec/transforms.h>

/******************************************************************************
 * helpers
 *****************************************************************************/
static xmlDocPtr
transformsTestCreateDoc(void) {
    static const char xml[] =
        "<root xmlns=\"urn:test\"><elem id=\"chapter1\">x</elem></root>";
    xmlDocPtr doc;

    doc = xmlReadMemory(xml, (int)strlen(xml), "transforms.xml", NULL,
        XML_PARSE_NONET | XML_PARSE_NOBLANKS);
    if(doc == NULL) {
        testLog("Error: failed to parse XML\n");
    }
    return(doc);
}

static xmlSecTransformCtxPtr
transformsTestCreateCtx(void) {
    xmlSecTransformCtxPtr ctx;

    ctx = xmlSecTransformCtxCreate();
    if(ctx == NULL) {
        testLog("Error: xmlSecTransformCtxCreate failed\n");
    }
    return(ctx);
}

static void
transformsTestCleanup(xmlDocPtr doc, xmlSecTransformCtxPtr ctx) {
    if(ctx != NULL) {
        xmlSecTransformCtxDestroy(ctx);
    }
    if(doc != NULL) {
        xmlFreeDoc(doc);
    }
}


/******************************************************************************
 * xmlSecTransformCtxSetUri
 *****************************************************************************/
static void
test_xmlSecTransformCtxSetUri_empty_uri(void) {
    static const xmlChar* expectedUri = NULL;
    static const xmlChar* expectedXptrExpr = NULL;
    xmlDocPtr doc;
    xmlSecTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    int ret;

    testStart("SetUri empty uri");

    doc = transformsTestCreateDoc();
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }
    hereNode = xmlDocGetRootElement(doc);
    if(hereNode == NULL) {
        testLog("Error: parsed XML does not have a root node\n");
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx = transformsTestCreateCtx();
    if(ctx == NULL) {
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }

    ret = xmlSecTransformCtxSetUri(ctx, BAD_CAST "", hereNode);
    if(ret < 0) {
        testLog("Error: xmlSecTransformCtxSetUri returned %d for an empty uri\n", ret);
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    if((ctx->uri != expectedUri) || (ctx->xptrExpr != expectedXptrExpr) || (ctx->first != NULL)) {
        testLog("Error: unexpected ctx state for an empty uri (uri='%s', xptrExpr='%s', first set)\n",
                (ctx->uri != NULL) ? (const char*)ctx->uri : "NULL",
                (ctx->xptrExpr != NULL) ? (const char*)ctx->xptrExpr : "NULL");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    transformsTestCleanup(doc, ctx);
    testFinishedSuccess();
}

static void
test_xmlSecTransformCtxSetUri_null_uri(void) {
    static const xmlChar* expectedUri = NULL;
    static const xmlChar* expectedXptrExpr = NULL;
    xmlDocPtr doc;
    xmlSecTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    int ret;

    testStart("SetUri NULL uri");

    doc = transformsTestCreateDoc();
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }
    hereNode = xmlDocGetRootElement(doc);
    if(hereNode == NULL) {
        testLog("Error: parsed XML does not have a root node\n");
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx = transformsTestCreateCtx();
    if(ctx == NULL) {
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }

    ret = xmlSecTransformCtxSetUri(ctx, NULL, hereNode);
    if(ret < 0) {
        testLog("Error: xmlSecTransformCtxSetUri returned %d for a NULL uri\n", ret);
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    if((ctx->uri != expectedUri) || (ctx->xptrExpr != expectedXptrExpr) || (ctx->first != NULL)) {
        testLog("Error: unexpected ctx state for a NULL uri (uri='%s', xptrExpr='%s', first set)\n",
                (ctx->uri != NULL) ? (const char*)ctx->uri : "NULL",
                (ctx->xptrExpr != NULL) ? (const char*)ctx->xptrExpr : "NULL");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    transformsTestCleanup(doc, ctx);
    testFinishedSuccess();
}

static void
test_xmlSecTransformCtxSetUri_plain_uri(void) {
    static const char uri[] = "http://example.com/bar.xml";
    static const xmlChar* expectedUri = BAD_CAST "http://example.com/bar.xml";
    static const xmlChar* expectedXptrExpr = NULL;
    xmlDocPtr doc;
    xmlSecTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    int ret;

    testStart("SetUri plain uri without fragment");

    doc = transformsTestCreateDoc();
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }
    hereNode = xmlDocGetRootElement(doc);
    if(hereNode == NULL) {
        testLog("Error: parsed XML does not have a root node\n");
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx = transformsTestCreateCtx();
    if(ctx == NULL) {
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx->enabledUris = xmlSecTransformUriTypeAny;

    ret = xmlSecTransformCtxSetUri(ctx, BAD_CAST uri, hereNode);
    if(ret < 0) {
        testLog("Error: xmlSecTransformCtxSetUri returned %d for a plain uri\n", ret);
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    if((ctx->uri == NULL) || (xmlStrcmp(ctx->uri, BAD_CAST expectedUri) != 0) ||
       (ctx->xptrExpr != expectedXptrExpr) || (ctx->first != NULL)) {
        testLog("Error: unexpected ctx state for a plain uri (uri='%s', xptrExpr='%s')\n",
                (ctx->uri != NULL) ? (const char*)ctx->uri : "NULL",
                (ctx->xptrExpr != NULL) ? (const char*)ctx->xptrExpr : "NULL");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    transformsTestCleanup(doc, ctx);
    testFinishedSuccess();
}

static void
test_xmlSecTransformCtxSetUri_trailing_empty_fragment(void) {
    /* a trailing empty fragment ("uri#") identifies the whole document, so it
     * must be treated as the uri "http://example.com/bar.xml" without a
     * fragment and without creating the XPointer transform */
    static const char uri[] = "http://example.com/bar.xml#";
    static const xmlChar* expectedUri = BAD_CAST "http://example.com/bar.xml";
    static const xmlChar* expectedXptrExpr = NULL;
    xmlDocPtr doc;
    xmlSecTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    int ret;

    testStart("SetUri trailing empty fragment is treated as the uri without a fragment");

    doc = transformsTestCreateDoc();
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }
    hereNode = xmlDocGetRootElement(doc);
    if(hereNode == NULL) {
        testLog("Error: parsed XML does not have a root node\n");
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx = transformsTestCreateCtx();
    if(ctx == NULL) {
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx->enabledUris = xmlSecTransformUriTypeAny;

    ret = xmlSecTransformCtxSetUri(ctx, BAD_CAST uri, hereNode);
    if(ret < 0) {
        testLog("Error: xmlSecTransformCtxSetUri returned %d for a uri with a trailing empty fragment\n", ret);
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    if((ctx->uri == NULL) || (xmlStrcmp(ctx->uri, BAD_CAST expectedUri) != 0) ||
       (ctx->xptrExpr != expectedXptrExpr) || (ctx->first != NULL)) {
        testLog("Error: unexpected ctx state for a trailing empty fragment (uri='%s', xptrExpr='%s')\n",
                (ctx->uri != NULL) ? (const char*)ctx->uri : "NULL",
                (ctx->xptrExpr != NULL) ? (const char*)ctx->xptrExpr : "NULL");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    transformsTestCleanup(doc, ctx);
    testFinishedSuccess();
}

static void
test_xmlSecTransformCtxSetUri_bare_empty_fragment(void) {
    /* a bare "#" identifies the whole document, so it must be accepted with
     * an empty uri part and no xpointer expression */
    static const char uri[] = "#";
    xmlDocPtr doc;
    xmlSecTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    int ret;

    testStart("SetUri bare empty fragment is accepted");

    doc = transformsTestCreateDoc();
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }
    hereNode = xmlDocGetRootElement(doc);
    if(hereNode == NULL) {
        testLog("Error: parsed XML does not have a root node\n");
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx = transformsTestCreateCtx();
    if(ctx == NULL) {
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }

    ret = xmlSecTransformCtxSetUri(ctx, BAD_CAST uri, hereNode);
    if(ret < 0) {
        testLog("Error: xmlSecTransformCtxSetUri returned %d for a bare empty fragment\n", ret);
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    if((ctx->uri == NULL) || (ctx->uri[0] != '\0') ||
       (ctx->xptrExpr != NULL) || (ctx->first != NULL)) {
        testLog("Error: unexpected ctx state for a bare empty fragment (uri='%s', xptrExpr='%s')\n",
                (ctx->uri != NULL) ? (const char*)ctx->uri : "NULL",
                (ctx->xptrExpr != NULL) ? (const char*)ctx->xptrExpr : "NULL");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    transformsTestCleanup(doc, ctx);
    testFinishedSuccess();
}

static void
test_xmlSecTransformCtxSetUri_xpointer_root_fragment(void) {
    static const char uri[] = "#xpointer(/)";
    static const xmlChar* expectedXptrExpr = BAD_CAST "#xpointer(/)";
    xmlDocPtr doc;
    xmlSecTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    int ret;

    testStart("SetUri #xpointer(/) fragment");

    doc = transformsTestCreateDoc();
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }
    hereNode = xmlDocGetRootElement(doc);
    if(hereNode == NULL) {
        testLog("Error: parsed XML does not have a root node\n");
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx = transformsTestCreateCtx();
    if(ctx == NULL) {
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }

    ret = xmlSecTransformCtxSetUri(ctx, BAD_CAST uri, hereNode);
    if(ret < 0) {
        testLog("Error: xmlSecTransformCtxSetUri returned %d for a #xpointer(/) uri\n", ret);
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    if((ctx->uri != NULL) ||
       ((ctx->xptrExpr == NULL) || (xmlStrcmp(ctx->xptrExpr, BAD_CAST expectedXptrExpr) != 0)) ||
       (ctx->first != NULL)) {
        testLog("Error: unexpected ctx state for a #xpointer(/) uri (uri='%s', xptrExpr='%s')\n",
                (ctx->uri != NULL) ? (const char*)ctx->uri : "NULL",
                (ctx->xptrExpr != NULL) ? (const char*)ctx->xptrExpr : "NULL");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    transformsTestCleanup(doc, ctx);
    testFinishedSuccess();
}

static void
test_xmlSecTransformCtxSetUri_bare_id_fragment(void) {
    static const char uri[] = "#chapter1";
    static const xmlChar* expectedXptrExpr = BAD_CAST "#chapter1";
    xmlDocPtr doc;
    xmlSecTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    int ret;

    testStart("SetUri bare id fragment creates the XPointer transform");

    doc = transformsTestCreateDoc();
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }
    hereNode = xmlDocGetRootElement(doc);
    if(hereNode == NULL) {
        testLog("Error: parsed XML does not have a root node\n");
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx = transformsTestCreateCtx();
    if(ctx == NULL) {
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }

    ret = xmlSecTransformCtxSetUri(ctx, BAD_CAST uri, hereNode);
    if(ret < 0) {
        testLog("Error: xmlSecTransformCtxSetUri returned %d for a bare id fragment\n", ret);
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    if((ctx->uri == NULL) || (ctx->uri[0] != '\0') ||
       ((ctx->xptrExpr == NULL) || (xmlStrcmp(ctx->xptrExpr, BAD_CAST expectedXptrExpr) != 0)) ||
       (ctx->first == NULL) || (!xmlSecTransformCheckId(ctx->first, xmlSecTransformXPointerId))) {
        testLog("Error: unexpected ctx state for a bare id fragment (uri='%s', xptrExpr='%s')\n",
                (ctx->uri != NULL) ? (const char*)ctx->uri : "NULL",
                (ctx->xptrExpr != NULL) ? (const char*)ctx->xptrExpr : "NULL");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    transformsTestCleanup(doc, ctx);
    testFinishedSuccess();
}

static void
test_xmlSecTransformCtxSetUri_uri_with_id_fragment(void) {
    static const char uri[] = "http://example.com/bar.xml#chapter1";
    static const xmlChar* expectedUri = BAD_CAST "http://example.com/bar.xml";
    static const xmlChar* expectedXptrExpr = BAD_CAST "#chapter1";
    xmlDocPtr doc;
    xmlSecTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    int ret;

    testStart("SetUri uri with id fragment creates the XPointer transform");

    doc = transformsTestCreateDoc();
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }
    hereNode = xmlDocGetRootElement(doc);
    if(hereNode == NULL) {
        testLog("Error: parsed XML does not have a root node\n");
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx = transformsTestCreateCtx();
    if(ctx == NULL) {
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx->enabledUris = xmlSecTransformUriTypeAny;

    ret = xmlSecTransformCtxSetUri(ctx, BAD_CAST uri, hereNode);
    if(ret < 0) {
        testLog("Error: xmlSecTransformCtxSetUri returned %d for a uri with an id fragment\n", ret);
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    if((ctx->uri == NULL) || (xmlStrcmp(ctx->uri, BAD_CAST expectedUri) != 0) ||
       ((ctx->xptrExpr == NULL) || (xmlStrcmp(ctx->xptrExpr, BAD_CAST expectedXptrExpr) != 0)) ||
       (ctx->first == NULL) || (!xmlSecTransformCheckId(ctx->first, xmlSecTransformXPointerId))) {
        testLog("Error: unexpected ctx state for a uri with an id fragment (uri='%s', xptrExpr='%s')\n",
                (ctx->uri != NULL) ? (const char*)ctx->uri : "NULL",
                (ctx->xptrExpr != NULL) ? (const char*)ctx->xptrExpr : "NULL");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    transformsTestCleanup(doc, ctx);
    testFinishedSuccess();
}

static void
test_xmlSecTransformCtxSetUri_uri_with_xpointer_fragment(void) {
    static const char uri[] = "http://example.com/bar.xml#xpointer(//foo)";
    static const xmlChar* expectedUri = BAD_CAST "http://example.com/bar.xml";
    static const xmlChar* expectedXptrExpr = BAD_CAST "#xpointer(//foo)";
    xmlDocPtr doc;
    xmlSecTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    int ret;

    testStart("SetUri uri with xpointer fragment creates the XPointer transform");

    doc = transformsTestCreateDoc();
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }
    hereNode = xmlDocGetRootElement(doc);
    if(hereNode == NULL) {
        testLog("Error: parsed XML does not have a root node\n");
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx = transformsTestCreateCtx();
    if(ctx == NULL) {
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx->enabledUris = xmlSecTransformUriTypeAny;

    ret = xmlSecTransformCtxSetUri(ctx, BAD_CAST uri, hereNode);
    if(ret < 0) {
        testLog("Error: xmlSecTransformCtxSetUri returned %d for a uri with an xpointer fragment\n", ret);
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    if((ctx->uri == NULL) || (xmlStrcmp(ctx->uri, BAD_CAST expectedUri) != 0) ||
       ((ctx->xptrExpr == NULL) || (xmlStrcmp(ctx->xptrExpr, BAD_CAST expectedXptrExpr) != 0)) ||
       (ctx->first == NULL) || (!xmlSecTransformCheckId(ctx->first, xmlSecTransformXPointerId))) {
        testLog("Error: unexpected ctx state for a uri with an xpointer fragment (uri='%s', xptrExpr='%s')\n",
                (ctx->uri != NULL) ? (const char*)ctx->uri : "NULL",
                (ctx->xptrExpr != NULL) ? (const char*)ctx->xptrExpr : "NULL");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    transformsTestCleanup(doc, ctx);
    testFinishedSuccess();
}

static void
test_xmlSecTransformCtxSetUri_remote_uri_disabled_by_default(void) {
    static const char uri[] = "http://example.com/bar.xml";
    xmlDocPtr doc;
    xmlSecTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    int ret;

    testStart("SetUri remote uri is rejected by the default uri type mask");

    doc = transformsTestCreateDoc();
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }
    hereNode = xmlDocGetRootElement(doc);
    if(hereNode == NULL) {
        testLog("Error: parsed XML does not have a root node\n");
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx = transformsTestCreateCtx();
    if(ctx == NULL) {
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }

    /* by default only the Empty and SameDocument uri types are enabled */
    ret = xmlSecTransformCtxSetUri(ctx, BAD_CAST uri, hereNode);
    if(ret >= 0) {
        testLog("Error: xmlSecTransformCtxSetUri accepted a remote uri with the default uri type mask\n");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    if((ctx->uri != NULL) || (ctx->xptrExpr != NULL)) {
        testLog("Error: unexpected ctx state after a rejected remote uri (uri='%s', xptrExpr='%s')\n",
                (ctx->uri != NULL) ? (const char*)ctx->uri : "NULL",
                (ctx->xptrExpr != NULL) ? (const char*)ctx->xptrExpr : "NULL");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    transformsTestCleanup(doc, ctx);
    testFinishedSuccess();
}

static void
test_xmlSecTransformCtxSetUri_local_uri_disabled_by_default(void) {
    static const char uri[] = "file:///tmp/test.xml";
    xmlDocPtr doc;
    xmlSecTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    int ret;

    testStart("SetUri local uri is rejected by the default uri type mask");

    doc = transformsTestCreateDoc();
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }
    hereNode = xmlDocGetRootElement(doc);
    if(hereNode == NULL) {
        testLog("Error: parsed XML does not have a root node\n");
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx = transformsTestCreateCtx();
    if(ctx == NULL) {
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }

    /* by default only the Empty and SameDocument uri types are enabled */
    ret = xmlSecTransformCtxSetUri(ctx, BAD_CAST uri, hereNode);
    if(ret >= 0) {
        testLog("Error: xmlSecTransformCtxSetUri accepted a local uri with the default uri type mask\n");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    if((ctx->uri != NULL) || (ctx->xptrExpr != NULL)) {
        testLog("Error: unexpected ctx state after a rejected local uri (uri='%s', xptrExpr='%s')\n",
                (ctx->uri != NULL) ? (const char*)ctx->uri : "NULL",
                (ctx->xptrExpr != NULL) ? (const char*)ctx->xptrExpr : "NULL");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    transformsTestCleanup(doc, ctx);
    testFinishedSuccess();
}

static void
test_xmlSecTransformCtxSetUri_local_uri_enabled(void) {
    static const char uri[] = "file:///tmp/test.xml";
    static const xmlChar* expectedUri = BAD_CAST "file:///tmp/test.xml";
    xmlDocPtr doc;
    xmlSecTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    int ret;

    testStart("SetUri local uri is accepted when the local uri type is enabled");

    doc = transformsTestCreateDoc();
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }
    hereNode = xmlDocGetRootElement(doc);
    if(hereNode == NULL) {
        testLog("Error: parsed XML does not have a root node\n");
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx = transformsTestCreateCtx();
    if(ctx == NULL) {
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx->enabledUris = xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument |
        xmlSecTransformUriTypeLocal;

    ret = xmlSecTransformCtxSetUri(ctx, BAD_CAST uri, hereNode);
    if(ret < 0) {
        testLog("Error: xmlSecTransformCtxSetUri returned %d for a local uri with the local uri type enabled\n", ret);
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    if((ctx->uri == NULL) || (xmlStrcmp(ctx->uri, BAD_CAST expectedUri) != 0) ||
       (ctx->xptrExpr != NULL) || (ctx->first != NULL)) {
        testLog("Error: unexpected ctx state for a local uri (uri='%s', xptrExpr='%s')\n",
                (ctx->uri != NULL) ? (const char*)ctx->uri : "NULL",
                (ctx->xptrExpr != NULL) ? (const char*)ctx->xptrExpr : "NULL");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    transformsTestCleanup(doc, ctx);
    testFinishedSuccess();
}

static void
test_xmlSecTransformCtxSetUri_visa3d_hack_bare_fragment(void) {
    static const char uri[] = "#12345";
    static const xmlChar* expectedXptrExpr = BAD_CAST "#12345";
    xmlDocPtr doc;
    xmlSecTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    int ret;

    testStart("SetUri visa3d hack creates the Visa3DHack transform for a bare fragment");

    doc = transformsTestCreateDoc();
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }
    hereNode = xmlDocGetRootElement(doc);
    if(hereNode == NULL) {
        testLog("Error: parsed XML does not have a root node\n");
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx = transformsTestCreateCtx();
    if(ctx == NULL) {
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx->flags |= XMLSEC_TRANSFORMCTX_FLAGS_USE_VISA3D_HACK;

    ret = xmlSecTransformCtxSetUri(ctx, BAD_CAST uri, hereNode);
    if(ret < 0) {
        testLog("Error: xmlSecTransformCtxSetUri returned %d for a bare fragment with the visa3d hack enabled\n", ret);
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    if((ctx->uri == NULL) || (ctx->uri[0] != '\0') ||
       ((ctx->xptrExpr == NULL) || (xmlStrcmp(ctx->xptrExpr, BAD_CAST expectedXptrExpr) != 0)) ||
       (ctx->first == NULL) || (!xmlSecTransformCheckId(ctx->first, xmlSecTransformVisa3DHackId))) {
        testLog("Error: unexpected ctx state for a bare fragment with the visa3d hack (uri='%s', xptrExpr='%s')\n",
                (ctx->uri != NULL) ? (const char*)ctx->uri : "NULL",
                (ctx->xptrExpr != NULL) ? (const char*)ctx->xptrExpr : "NULL");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    transformsTestCleanup(doc, ctx);
    testFinishedSuccess();
}

static void
test_xmlSecTransformCtxSetUri_visa3d_hack_uri_with_fragment(void) {
    static const char uri[] = "http://example.com/bar.xml#12345";
    static const xmlChar* expectedUri = BAD_CAST "http://example.com/bar.xml";
    static const xmlChar* expectedXptrExpr = BAD_CAST "#12345";
    xmlDocPtr doc;
    xmlSecTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    int ret;

    testStart("SetUri visa3d hack creates the Visa3DHack transform for a uri with a fragment");

    doc = transformsTestCreateDoc();
    if(doc == NULL) {
        testFinishedFailure();
        return;
    }
    hereNode = xmlDocGetRootElement(doc);
    if(hereNode == NULL) {
        testLog("Error: parsed XML does not have a root node\n");
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx = transformsTestCreateCtx();
    if(ctx == NULL) {
        transformsTestCleanup(doc, NULL);
        testFinishedFailure();
        return;
    }
    ctx->flags |= XMLSEC_TRANSFORMCTX_FLAGS_USE_VISA3D_HACK;
    ctx->enabledUris = xmlSecTransformUriTypeAny;

    ret = xmlSecTransformCtxSetUri(ctx, BAD_CAST uri, hereNode);
    if(ret < 0) {
        testLog("Error: xmlSecTransformCtxSetUri returned %d for a uri with a fragment and the visa3d hack enabled\n", ret);
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    if((ctx->uri == NULL) || (xmlStrcmp(ctx->uri, BAD_CAST expectedUri) != 0) ||
       ((ctx->xptrExpr == NULL) || (xmlStrcmp(ctx->xptrExpr, BAD_CAST expectedXptrExpr) != 0)) ||
       (ctx->first == NULL) || (!xmlSecTransformCheckId(ctx->first, xmlSecTransformVisa3DHackId))) {
        testLog("Error: unexpected ctx state for a uri with a fragment and the visa3d hack (uri='%s', xptrExpr='%s')\n",
                (ctx->uri != NULL) ? (const char*)ctx->uri : "NULL",
                (ctx->xptrExpr != NULL) ? (const char*)ctx->xptrExpr : "NULL");
        transformsTestCleanup(doc, ctx);
        testFinishedFailure();
        return;
    }

    transformsTestCleanup(doc, ctx);
    testFinishedSuccess();
}


/******************************************************************************
 * exported entry point
 *****************************************************************************/
int
test_transforms(void) {
    int success = 1;

    testGroupStart("xmlSecTransformCtxSetUri");
    test_xmlSecTransformCtxSetUri_empty_uri();
    test_xmlSecTransformCtxSetUri_null_uri();
    test_xmlSecTransformCtxSetUri_plain_uri();
    test_xmlSecTransformCtxSetUri_trailing_empty_fragment();
    test_xmlSecTransformCtxSetUri_bare_empty_fragment();
    test_xmlSecTransformCtxSetUri_xpointer_root_fragment();
    test_xmlSecTransformCtxSetUri_bare_id_fragment();
    test_xmlSecTransformCtxSetUri_uri_with_id_fragment();
    test_xmlSecTransformCtxSetUri_uri_with_xpointer_fragment();
    test_xmlSecTransformCtxSetUri_remote_uri_disabled_by_default();
    test_xmlSecTransformCtxSetUri_local_uri_disabled_by_default();
    test_xmlSecTransformCtxSetUri_local_uri_enabled();
    test_xmlSecTransformCtxSetUri_visa3d_hack_bare_fragment();
    test_xmlSecTransformCtxSetUri_visa3d_hack_uri_with_fragment();
    if(testGroupFinished() != 1) { success = 0; }

    return(success);
}
