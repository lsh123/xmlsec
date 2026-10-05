/*
 * xmlsec OPC Relationship Transform fuzz target.
 *
 * The input is a single XML document containing a ds:Transform configuration
 * and an OPC Relationships element. The relationship subtree is copied into a
 * separate in-memory document before execution, matching the transform's real
 * input model without allowing file or network access.
 */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>

#include <xmlsec/errors.h>
#include <xmlsec/nodeset.h>
#include <xmlsec/strings.h>
#include <xmlsec/transforms.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/parser.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

static int g_initialized = 0;
static int g_init_failed = 0;

static void ignore_error(void* ctx, const char* msg, ...) {
    (void)ctx;
    (void)msg;
}

static void ignore_xmlsec_error(const char* file, int line, const char* func,
                                const char* errorObject, const char* errorSubject,
                                int reason, const char* msg) {
    (void)file;
    (void)line;
    (void)func;
    (void)errorObject;
    (void)errorSubject;
    (void)reason;
    (void)msg;
}

static int do_init(void) {
    xmlInitParser();

    if (xmlSecInit() < 0) {
        return -1;
    }
    if (xmlSecCheckVersion() != 1) {
        xmlSecShutdown();
        return -1;
    }

    xmlSetGenericErrorFunc(NULL, &ignore_error);
    xmlSecErrorsSetCallback(&ignore_xmlsec_error);
    return 0;
}

/* Maximum recursion depth for find_relationships(). The input is parsed with
 * xmlSecParserGetDefaultOptions(), which includes XML_PARSE_HUGE (see
 * src/parser.c), so libxml2's element-nesting limit does not apply: inputs
 * nested beyond this cap parse fine and are then silently skipped by
 * find_relationships() (a coverage loss, not a crash). The cap bounds the
 * recursion as defense-in-depth so the stack cannot be exhausted regardless
 * of the parser depth limit. */
#define RELATIONSHIPS_MAX_DEPTH 10000

static xmlNodePtr find_relationships(xmlNodePtr node, int depth) {
    xmlNodePtr cur;

    if (depth >= RELATIONSHIPS_MAX_DEPTH) {
        return NULL;
    }
    for (cur = node; cur != NULL; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE && cur->ns != NULL &&
            cur->ns->href != NULL &&
            xmlStrEqual(cur->ns->href, xmlSecRelationshipsNs)) {
            return cur;
        }
        if (cur->children != NULL) {
            xmlNodePtr found = find_relationships(cur->children, depth + 1);
            if (found != NULL) {
                return found;
            }
        }
    }
    return NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    xmlDocPtr input_doc = NULL;
    xmlDocPtr relationships_doc = NULL;
    xmlNodePtr root;
    xmlNodePtr transform_node;
    xmlNodePtr relationships_node;
    xmlNodePtr relationships_copy;
    xmlSecTransformCtxPtr transform_ctx = NULL;
    xmlSecNodeSetPtr nodes = NULL;

    if (!g_initialized) {
        g_init_failed = (do_init() < 0);
        g_initialized = 1;
    }
    if (g_init_failed || size == 0 || size > (size_t)INT_MAX) {
        return 0;
    }

    input_doc = xmlReadMemory((const char*)data, (int)size, "fuzz.xml", NULL,
        xmlSecParserGetDefaultOptions() | XML_PARSE_PEDANTIC | XML_PARSE_NONET);
    if (input_doc == NULL || (root = xmlDocGetRootElement(input_doc)) == NULL) {
        goto done;
    }

    transform_node = xmlSecFindNode(root, xmlSecNodeTransform, xmlSecDSigNs);
    relationships_node = find_relationships(root, 0);
    if (transform_node == NULL || relationships_node == NULL) {
        goto done;
    }

    relationships_doc = xmlNewDoc(BAD_CAST "1.0");
    if (relationships_doc == NULL) {
        goto done;
    }
    relationships_copy = xmlDocCopyNode(relationships_node, relationships_doc, 1);
    if (relationships_copy == NULL) {
        goto done;
    }
    xmlDocSetRootElement(relationships_doc, relationships_copy);

    transform_ctx = xmlSecTransformCtxCreate();
    if (transform_ctx == NULL) {
        goto done;
    }
    transform_ctx->enabledUris = xmlSecTransformUriTypeEmpty |
                                 xmlSecTransformUriTypeSameDocument;
    transform_ctx->maxDepth = 64;
    if (xmlSecTransformCtxNodeRead(transform_ctx, transform_node,
                                   xmlSecTransformUsageDSigTransform) == NULL) {
        goto done;
    }

    nodes = xmlSecNodeSetCreate(relationships_doc, NULL, xmlSecNodeSetTree);
    if (nodes == NULL) {
        goto done;
    }
    (void)xmlSecTransformCtxXmlExecute(transform_ctx, nodes);

done:
    if (nodes != NULL) {
        xmlSecNodeSetDestroy(nodes);
    }
    if (transform_ctx != NULL) {
        xmlSecTransformCtxDestroy(transform_ctx);
    }
    if (relationships_doc != NULL) {
        xmlFreeDoc(relationships_doc);
    }
    if (input_doc != NULL) {
        xmlFreeDoc(input_doc);
    }
    return 0;
}