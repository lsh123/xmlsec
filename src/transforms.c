/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Transform object functions.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_core_transforms
 * @brief XMLDsig and XMLEnc transforms.
 * The [Transforms Element](http://www.w3.org/TR/xmldsig-core/#sec-Transforms)
 * contains an ordered list of Transform elements; these describe how the signer
 * obtained the data object that was digested.
 * Schema Definition:
 * @code{.xml}
 *  <element name="Transforms" type="ds:TransformsType"/>
 *  <complexType name="TransformsType">
 *    <sequence>
 *      <element ref="ds:Transform" maxOccurs="unbounded"/>
 *    </sequence>
 *   </complexType>
 *  <element name="Transform" type="ds:TransformType"/>
 *  <complexType name="TransformType" mixed="true">
 *    <choice minOccurs="0" maxOccurs="unbounded">
 *      <any namespace="##other" processContents="lax"/>
 *      <!-- (1,1) elements from (0,unbounded) namespaces -->
 *      <element name="XPath" type="string"/>
 *    </choice>
 *    <attribute name="Algorithm" type="anyURI" use="required"/>
 *  </complexType>
 * @endcode
 * DTD:
 * @code{.xml}
 *  <!ELEMENT Transforms (Transform+)>
 *  <!ELEMENT Transform (#PCDATA|XPath %Transform.ANY;)* >
 *  <!ATTLIST Transform Algorithm    CDATA    #REQUIRED >
 *  <!ELEMENT XPath (#PCDATA) >
 * @endcode
 */
#include "globals.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpointer.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/base64.h>
#include <xmlsec/io.h>
#include <xmlsec/membuf.h>
#include <xmlsec/parser.h>
#include <xmlsec/errors.h>

#include "xslt.h"
#include "cast_helpers.h"
#include "transform_helpers.h"

#define XMLSEC_TRANSFORM_XPOINTER_TMPL "xpointer(id(\'%s\'))"

/******************************************************************************
 *
 * Global xmlSecTransformIds list functions
 *
  *****************************************************************************/
static xmlSecPtrList xmlSecAllTransformIds;


/**
 * @brief Gets global registered transform klasses list.
 *
 * @return the pointer to list of all registered transform klasses.
 */
xmlSecPtrListPtr
xmlSecTransformIdsGet(void) {
    return(&xmlSecAllTransformIds);
}

/**
 * @brief Initializes the transform klasses.
 * @details Initializes the transform klasses. This function is called from the
 * #xmlSecInit function and the application should not call it directly.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformIdsInit(void) {
    int ret;

    ret = xmlSecPtrListInitialize(xmlSecTransformIdsGet(), xmlSecTransformIdListId);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListInitialize(xmlSecTransformIdListId)", NULL);
        return(-1);
    }

    ret = xmlSecTransformIdsRegisterDefault();
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformIdsRegisterDefault", NULL);
        return(-1);
    }

#ifndef XMLSEC_NO_XSLT
    xmlSecTransformXsltInitialize();
#endif /* XMLSEC_NO_XSLT */

    return(0);
}

/**
 * @brief Shuts down the transform klasses.
 * @details Shuts down the keys data klasses. This function is called from the
 * #xmlSecShutdown function and the application should not call it directly.
 */
void
xmlSecTransformIdsShutdown(void) {
#ifndef XMLSEC_NO_XSLT
    xmlSecTransformXsltShutdown();
#endif /* XMLSEC_NO_XSLT */

    xmlSecPtrListFinalize(xmlSecTransformIdsGet());
}

/**
 * @brief Registers a transform klass in the global list.
 * @details Registers @p id in the global list of transform klasses.
 * @param id the transform klass.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformIdsRegister(xmlSecTransformId id) {
    int ret;

    xmlSecAssert2(id != xmlSecTransformIdUnknown, -1);

    ret = xmlSecPtrListAdd(xmlSecTransformIdsGet(), (xmlSecPtr)id);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListAdd",
                            xmlSecTransformKlassGetName(id));
        return(-1);
    }

    return(0);
}

/**
 * @brief Registers default XML Security Library transform klasses.
 * @details Registers default (implemented by XML Security Library)
 * transform klasses: XPath transform, Base64 transform, ...
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformIdsRegisterDefault(void) {
    if(xmlSecTransformIdsRegister(xmlSecTransformBase64Id) < 0) {
        xmlSecInternalError("xmlSecTransformIdsRegister(xmlSecTransformBase64Id)", NULL);
        return(-1);
    }

    if(xmlSecTransformIdsRegister(xmlSecTransformEnvelopedId) < 0) {
        xmlSecInternalError("xmlSecTransformIdsRegister(xmlSecTransformEnvelopedId)", NULL);
        return(-1);
    }

    /* c14n methods */
    if(xmlSecTransformIdsRegister(xmlSecTransformInclC14NId) < 0) {
        xmlSecInternalError("xmlSecTransformIdsRegister(xmlSecTransformInclC14NId)", NULL);
        return(-1);
    }
    if(xmlSecTransformIdsRegister(xmlSecTransformInclC14NWithCommentsId) < 0) {
        xmlSecInternalError("xmlSecTransformIdsRegister(xmlSecTransformInclC14NWithCommentsId)", NULL);
        return(-1);
    }
    if(xmlSecTransformIdsRegister(xmlSecTransformInclC14N11Id) < 0) {
        xmlSecInternalError("xmlSecTransformIdsRegister(xmlSecTransformInclC14N11Id)", NULL);
        return(-1);
    }
    if(xmlSecTransformIdsRegister(xmlSecTransformInclC14N11WithCommentsId) < 0) {
        xmlSecInternalError("xmlSecTransformIdsRegister(xmlSecTransformInclC14N11WithCommentsId)", NULL);
        return(-1);
    }
    if(xmlSecTransformIdsRegister(xmlSecTransformExclC14NId) < 0) {
        xmlSecInternalError("xmlSecTransformIdsRegister(xmlSecTransformExclC14NId)", NULL);
        return(-1);
    }
    if(xmlSecTransformIdsRegister(xmlSecTransformExclC14NWithCommentsId) < 0) {
        xmlSecInternalError("xmlSecTransformIdsRegister(xmlSecTransformExclC14NWithCommentsId)", NULL);
        return(-1);
    }

    if(xmlSecTransformIdsRegister(xmlSecTransformXPathId) < 0) {
        xmlSecInternalError("xmlSecTransformIdsRegister(xmlSecTransformXPathId)", NULL);
        return(-1);
    }

    if(xmlSecTransformIdsRegister(xmlSecTransformXPath2Id) < 0) {
        xmlSecInternalError("xmlSecTransformIdsRegister(xmlSecTransformXPath2Id)", NULL);
        return(-1);
    }

    if(xmlSecTransformIdsRegister(xmlSecTransformXPointerId) < 0) {
        xmlSecInternalError("xmlSecTransformIdsRegister(xmlSecTransformXPointerId)", NULL);
        return(-1);
    }

    if(xmlSecTransformIdsRegister(xmlSecTransformRelationshipId) < 0) {
        xmlSecInternalError("xmlSecTransformIdsRegister(xmlSecTransformRelationshipId)", NULL);
        return(-1);
    }

#ifndef XMLSEC_NO_XSLT
    if(xmlSecTransformIdsRegister(xmlSecTransformXsltId) < 0) {
        xmlSecInternalError("xmlSecTransformIdsRegister(xmlSecTransformXsltId)", NULL);
        return(-1);
    }
#endif /* XMLSEC_NO_XSLT */

    return(0);
}

/******************************************************************************
 *
 * utils
 *
  *****************************************************************************/
/**
 * @brief Checks if @p uri matches expected type @p type.
 * @param type the expected URI type.
 * @param uri the uri for checking.
 *
 * @return 1 if @p uri matches @p type, 0 if not or a negative value
 * if an error occurs.
 */
int
xmlSecTransformUriTypeCheck(xmlSecTransformUriType type, const xmlChar* uri) {
    xmlSecTransformUriType uriType = 0;

    if((uri == NULL) || (xmlSecStrlen(uri) == 0)) {
        uriType = xmlSecTransformUriTypeEmpty;
    } else if(uri[0] == '#') {
        uriType = xmlSecTransformUriTypeSameDocument;
    } else if(xmlStrncmp(uri, BAD_CAST "file://", 7) == 0) {
        uriType = xmlSecTransformUriTypeLocal;
    } else {
        uriType = xmlSecTransformUriTypeRemote;
    }
    return(((uriType & type) != 0) ? 1 : 0);
}



/******************************************************************************
 *
 * xmlSecTransformCtx
 *
  *****************************************************************************/
static xmlSecSize g_xmlSecTransformCtxDefaultBinaryChunkSize = (64*1024); /* 64kb */

/**
 * @brief Gets the default binary chunk size.
 * @details Gets the binary chunk size. Increasing the chunk size improves
 * XMLSec library performance at the expense of increased memory usage.
 *
 * @return the current binary processing chunk size.
 */
xmlSecSize
xmlSecTransformCtxGetDefaultBinaryChunkSize(void) {
    return(g_xmlSecTransformCtxDefaultBinaryChunkSize);
}


/**
 * @brief Sets the default binary chunk size.
 * @details Sets the default binary chunk size. Increasing the chunk size improves
 * XMLSec library performance at the expense of increased memory usage.
 * This function is not thread safe and should only be called during initialization.
 * @param binaryChunkSize the new binary chunk size (must be greater than zero).
 */
void
xmlSecTransformCtxSetDefaultBinaryChunkSize(xmlSecSize binaryChunkSize) {
    xmlSecAssert(binaryChunkSize > 0);
    g_xmlSecTransformCtxDefaultBinaryChunkSize = binaryChunkSize;
}



/**
 * @brief Creates a transforms chain processing context.
 * @details Creates transforms chain processing context.
 * The caller is responsible for destroying returned object by calling
 * #xmlSecTransformCtxDestroy function.
 *
 * @return pointer to newly allocated context object or NULL if an error
 * occurs.
 */
xmlSecTransformCtxPtr
xmlSecTransformCtxCreate(void) {
    xmlSecTransformCtxPtr ctx;
    int ret;

    /* Allocate a new xmlSecTransform and fill the fields. */
    ctx = (xmlSecTransformCtxPtr)xmlMalloc(sizeof(xmlSecTransformCtx));
    if(ctx == NULL) {
        xmlSecMallocError(sizeof(xmlSecTransformCtx), NULL);
        return(NULL);
    }

    ret = xmlSecTransformCtxInitialize(ctx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformCtxInitialize", NULL);
        xmlSecTransformCtxDestroy(ctx);
        return(NULL);
    }

    return(ctx);
}

/**
 * @brief Destroys a transforms chain processing context.
 * @details Destroy context object created with #xmlSecTransformCtxCreate function.
 * @param ctx the pointer to transforms chain processing context.
 */
void
xmlSecTransformCtxDestroy(xmlSecTransformCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    xmlSecTransformCtxFinalize(ctx);
    xmlFree(ctx);
}

/**
 * @brief Initializes a transforms chain processing context.
 * @details Initializes transforms chain processing context.
 * The caller is responsible for cleaning up returned object by calling
 * #xmlSecTransformCtxFinalize function.
 * @param ctx the pointer to transforms chain processing context.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformCtxInitialize(xmlSecTransformCtxPtr ctx) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecTransformCtx));

    ret = xmlSecPtrListInitialize(&(ctx->enabledTransforms), xmlSecTransformIdListId);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListInitialize(xmlSecTransformIdListId)", NULL);
        return(-1);
    }

    ctx->enabledUris = xmlSecTransformUriTypeAny;
    ctx->binaryChunkSize = xmlSecTransformCtxGetDefaultBinaryChunkSize();
    return(0);
}

/**
 * @brief Cleans up a transforms chain processing context.
 * @details Cleans up @p ctx object initialized with #xmlSecTransformCtxInitialize function.
 * @param ctx the pointer to transforms chain processing context.
 */
void
xmlSecTransformCtxFinalize(xmlSecTransformCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    xmlSecTransformCtxReset(ctx);
    xmlSecPtrListFinalize(&(ctx->enabledTransforms));
    memset(ctx, 0, sizeof(xmlSecTransformCtx));
}

/**
 * @brief Resets transforms context for new processing.
 * @param ctx the pointer to transforms chain processing context.
 */
void
xmlSecTransformCtxReset(xmlSecTransformCtxPtr ctx) {
    xmlSecTransformPtr transform, tmp;

    xmlSecAssert(ctx != NULL);

    ctx->result = NULL;
    ctx->status = xmlSecTransformStatusNone;

    /* destroy uri */
    if(ctx->uri != NULL) {
        xmlFree(ctx->uri);
        ctx->uri = NULL;
    }
    if(ctx->xptrExpr != NULL) {
        xmlFree(ctx->xptrExpr);
        ctx->xptrExpr = NULL;
    }

    /* destroy transforms chain */
    for(transform = ctx->first; transform != NULL; transform = tmp) {
        tmp = transform->next;
        xmlSecTransformDestroy(transform);
    }
    ctx->first = ctx->last = NULL;
}

/**
 * @brief Copies user settings from @p src context to @p dst.
 * @details Copies user settings from @p src context to @p dst.
 * @param dst the pointer to destination transforms chain processing context.
 * @param src the pointer to source transforms chain processing context.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecTransformCtxCopyUserPref(xmlSecTransformCtxPtr dst, xmlSecTransformCtxPtr src) {
    int ret;

    xmlSecAssert2(dst != NULL, -1);
    xmlSecAssert2(src != NULL, -1);

    dst->userData        = src->userData;
    dst->flags           = src->flags;
    dst->flags2          = src->flags2;
    dst->enabledUris     = src->enabledUris;
    dst->preExecCallback = src->preExecCallback;

    ret = xmlSecPtrListCopy(&(dst->enabledTransforms), &(src->enabledTransforms));
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListCopy(enabledTransforms)", NULL);
        return(-1);
    }

    return(0);
}

/**
 * @brief Connects a transform to the end of the chain in @p ctx.
 * @details Connects the @p transform to the end of the chain of transforms in the @p ctx
 * (see #xmlSecTransformConnect function for details).
 * @param ctx the pointer to transforms chain processing context.
 * @param transform the pointer to new transform.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecTransformCtxAppend(xmlSecTransformCtxPtr ctx, xmlSecTransformPtr transform) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->status == xmlSecTransformStatusNone, -1);
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);

    if(ctx->last != NULL) {
        ret = xmlSecTransformConnect(ctx->last, transform, ctx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformConnect",
                                xmlSecTransformGetName(transform));
            return(-1);
        }
    } else {
        xmlSecAssert2(ctx->first == NULL, -1);
        ctx->first = transform;
    }
    ctx->last = transform;

    return(0);
}

/**
 * @brief Connects a transform to the beginning of the chain in @p ctx.
 * @details Connects the @p transform to the beggining of the chain of transforms in the @p ctx
 * (see #xmlSecTransformConnect function for details).
 * @param ctx the pointer to transforms chain processing context.
 * @param transform the pointer to new transform.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecTransformCtxPrepend(xmlSecTransformCtxPtr ctx, xmlSecTransformPtr transform) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->status == xmlSecTransformStatusNone, -1);
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);

    if(ctx->first != NULL) {
        ret = xmlSecTransformConnect(transform, ctx->first, ctx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformConnect",
                                xmlSecTransformGetName(transform));
            return(-1);
        }
    } else {
        xmlSecAssert2(ctx->last == NULL, -1);
        ctx->last = transform;
    }
    ctx->first = transform;

    return(0);
}

/**
 * @brief Creates a transform and appends it to the chain in @p ctx.
 * @details Creates new transform and connects it to the end of the chain of
 * transforms in the @p ctx (see #xmlSecTransformConnect function for details).
 * @param ctx the pointer to transforms chain processing context.
 * @param id the new transform klass.
 *
 * @return pointer to newly created transform or NULL if an error occurs.
 */
xmlSecTransformPtr
xmlSecTransformCtxCreateAndAppend(xmlSecTransformCtxPtr ctx, xmlSecTransformId id) {
    xmlSecTransformPtr transform;
    int ret;

    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->status == xmlSecTransformStatusNone, NULL);
    xmlSecAssert2(id != xmlSecTransformIdUnknown, NULL);

    transform = xmlSecTransformCreate(id);
    if(!xmlSecTransformIsValid(transform)) {
        xmlSecInternalError("xmlSecTransformCreate",
                            xmlSecTransformKlassGetName(id));
        return(NULL);
    }

    ret = xmlSecTransformCtxAppend(ctx, transform);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformCtxAppend",
                            xmlSecTransformKlassGetName(id));
        xmlSecTransformDestroy(transform);
        return(NULL);
    }

    return(transform);
}

/**
 * @brief Creates a transform and prepends it to the chain in @p ctx.
 * @details Creates new transform and connects it to the end of the chain of
 * transforms in the @p ctx (see #xmlSecTransformConnect function for details).
 * @param ctx the pointer to transforms chain processing context.
 * @param id the new transform klass.
 *
 * @return pointer to newly created transform or NULL if an error occurs.
 */
xmlSecTransformPtr
xmlSecTransformCtxCreateAndPrepend(xmlSecTransformCtxPtr ctx, xmlSecTransformId id) {
    xmlSecTransformPtr transform;
    int ret;

    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->status == xmlSecTransformStatusNone, NULL);
    xmlSecAssert2(id != xmlSecTransformIdUnknown, NULL);

    transform = xmlSecTransformCreate(id);
    if(!xmlSecTransformIsValid(transform)) {
        xmlSecInternalError("xmlSecTransformCreate",
                            xmlSecTransformKlassGetName(id));
        return(NULL);
    }

    ret = xmlSecTransformCtxPrepend(ctx, transform);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformCtxPrepend",
                            xmlSecTransformGetName(transform));
        xmlSecTransformDestroy(transform);
        return(NULL);
    }

    return(transform);
}

/**
 * @brief Reads a transform from a node and appends it to the chain.
 * @details Reads the transform from the @p node and appends it to the current chain
 * of transforms in @p ctx.
 * @param ctx the pointer to transforms chain processing context.
 * @param node the pointer to transform's node.
 * @param usage the transform's usage (signature, encryption, etc.).
 *
 * @return pointer to newly created transform or NULL if an error occurs.
 */
xmlSecTransformPtr
xmlSecTransformCtxNodeRead(xmlSecTransformCtxPtr ctx, xmlNodePtr node,
                           xmlSecTransformUsage usage) {
    xmlSecTransformPtr transform;
    int ret;

    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->status == xmlSecTransformStatusNone, NULL);
    xmlSecAssert2(node != NULL, NULL);

    transform = xmlSecTransformNodeRead(node, usage, ctx);
    if(transform == NULL) {
        xmlSecInternalError("xmlSecTransformNodeRead",
                            xmlSecNodeGetName(node));
        return(NULL);
    }

    ret = xmlSecTransformCtxAppend(ctx, transform);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformCtxAppend",
                            xmlSecTransformGetName(transform));
        xmlSecTransformDestroy(transform);
        return(NULL);
    }

    return(transform);
}

/**
 * @brief Reads transforms from &lt;dsig:Transform/&gt; children and appends to chain.
 * @details Reads transforms from the &lt;dsig:Transform/&gt; children of the @p node and
 * appends them to the current transforms chain in @p ctx object.
 * @param ctx the pointer to transforms chain processing context.
 * @param node the pointer to &lt;dsig:Transform/&gt; nodes parent node.
 * @param usage the transform's usage (signature, encryption, etc.).
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecTransformCtxNodesListRead(xmlSecTransformCtxPtr ctx, xmlNodePtr node, xmlSecTransformUsage usage) {
    xmlSecTransformPtr transform;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->status == xmlSecTransformStatusNone, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = xmlSecGetNextElementNode(node->children);
    while((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeTransform, xmlSecDSigNs)) {
        transform = xmlSecTransformNodeRead(cur, usage, ctx);
        if(transform == NULL) {
            xmlSecInternalError("xmlSecTransformNodeRead",
                                xmlSecNodeGetName(cur));
            return(-1);
        }
        transform->flags |= XMLSEC_TRANSFORM_FLAGS_USER_SPECIFIED;

        ret = xmlSecTransformCtxAppend(ctx, transform);
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformCtxAppend",
                                xmlSecTransformGetName(transform));
            xmlSecTransformDestroy(transform);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }
    return(0);
}

/**
 * @brief Parses URI and adds xpointer transforms if required.
 * @details Parses uri and adds xpointer transforms if required.
 *
 * The following examples demonstrate what the URI attribute identifies and
 * how it is dereferenced
 * (http://www.w3.org/TR/xmldsig-core/#sec-ReferenceProcessingModel):
 *
 * - `URI="http://example.com/bar.xml"`
 * identifies the octets that represent the external resource
 * 'http://example.com/bar.xml', that is probably an XML document given
 * its file extension.
 *
 * - `URI="http://example.com/bar.xml#chapter1"`
 * identifies the element with ID attribute value 'chapter1' of the
 * external XML resource 'http://example.com/bar.xml', provided as an
 * octet stream. Again, for the sake of interoperability, the element
 * identified as 'chapter1' should be obtained using an XPath transform
 * rather than a URI fragment (barename XPointer resolution in external
 * resources is not REQUIRED in this specification).
 *
 * - `URI=""`
 * identifies the node-set (minus any comment nodes) of the XML resource
 * containing the signature
 *
 * - `URI="#chapter1"`
 * identifies a node-set containing the element with ID attribute value
 * 'chapter1' of the XML resource containing the signature. XML Signature
 * (and its applications) modify this node-set to include the element plus
 * all descendants including namespaces and attributes -- but not comments.
 *
 * @param ctx the pointer to transforms chain processing context.
 * @param uri the URI.
 * @param hereNode the pointer to "here" node required by some
 *                      XML transforms (may be NULL).
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecTransformCtxSetUri(xmlSecTransformCtxPtr ctx, const xmlChar* uri, xmlNodePtr hereNode) {
    xmlSecNodeSetType nodeSetType = xmlSecNodeSetTree;
    const xmlChar* xptr;
    xmlChar* buf = NULL;
    int uriLen;
    int useVisa3DHack = 0;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->uri == NULL, -1);
    xmlSecAssert2(ctx->xptrExpr == NULL, -1);
    xmlSecAssert2(ctx->status == xmlSecTransformStatusNone, -1);
    xmlSecAssert2(hereNode != NULL, -1);

    /* check uri */
    if(xmlSecTransformUriTypeCheck(ctx->enabledUris, uri) != 1) {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_KEY_DATA_SIZE, NULL, "uri=%s", xmlSecErrorsSafeString(uri));
        goto done;
    }

    /* is it an empty uri? */
    if((uri == NULL) || (xmlSecStrlen(uri) == 0)) {
        res = 0;
        goto done;
    }

    /* do we have barename or full xpointer? */
    xptr = xmlStrchr(uri, '#');
    if(xptr == NULL){
        ctx->uri = xmlStrdup(uri);
        if(ctx->uri == NULL) {
            xmlSecStrdupError(uri, NULL);
            goto done;
        }
        /* nothing else to do */
        res = 0;
        goto done;
    } else if(xmlStrcmp(uri, BAD_CAST "#xpointer(/)") == 0) {
        ctx->xptrExpr = xmlStrdup(uri);
        if(ctx->xptrExpr == NULL) {
            xmlSecStrdupError(uri, NULL);
            goto done;
        }
        /* nothing else to do */
        res = 0;
        goto done;
    }

    XMLSEC_SAFE_CAST_PTRDIFF_TO_INT((xptr - uri), uriLen, return(-1), NULL);
    ctx->uri = xmlStrndup(uri, uriLen);
    if(ctx->uri == NULL) {
        xmlSecStrdupError(uri, NULL);
        goto done;
    }

    ctx->xptrExpr = xmlStrdup(xptr);
    if(ctx->xptrExpr == NULL) {
        xmlSecStrdupError(xptr, NULL);
        goto done;
    }

    /* do we have barename or full xpointer? */
    xmlSecAssert2(xptr != NULL, -1);
    if((xmlStrncmp(xptr, BAD_CAST "#xpointer(", 10) == 0) || (xmlStrncmp(xptr, BAD_CAST "#xmlns(", 7) == 0)) {
        ++xptr;
        nodeSetType = xmlSecNodeSetTree;
    } else if((ctx->flags & XMLSEC_TRANSFORMCTX_FLAGS_USE_VISA3D_HACK) != 0) {
        ++xptr;
        nodeSetType = xmlSecNodeSetTreeWithoutComments;
        useVisa3DHack = 1;
    } else {
        xmlSecSize size;
        int len;

        /* we need to add "xpointer(id('..')) because otherwise we have
         * problems with numeric ("111" and so on) and other "strange" ids */
        len = xmlStrlen(BAD_CAST XMLSEC_TRANSFORM_XPOINTER_TMPL) + xmlStrlen(xptr) + 2;
        XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return(-1), NULL);
        buf = (xmlChar*)xmlMalloc(size * sizeof(xmlChar));
        if(buf == NULL) {
            xmlSecMallocError(size * sizeof(xmlChar), NULL);
            goto done;
        }
        ret = xmlStrPrintf(buf, len, XMLSEC_TRANSFORM_XPOINTER_TMPL, xptr + 1);
        if(ret < 0) {
            xmlSecXmlError("xmlStrPrintf", NULL);
            goto done;
        }
        xptr = buf;
        nodeSetType = xmlSecNodeSetTreeWithoutComments;
    }

    if(useVisa3DHack == 0) {
        xmlSecTransformPtr transform;

        /* we need to create XPonter transform to execute expr */
        transform = xmlSecTransformCtxCreateAndPrepend(ctx, xmlSecTransformXPointerId);
        if(!xmlSecTransformIsValid(transform)) {
            xmlSecInternalError("xmlSecTransformCtxCreateAndPrepend(xmlSecTransformXPointerId)", NULL);
            goto done;
        }

        ret = xmlSecTransformXPointerSetExpr(transform, xptr, nodeSetType, hereNode);
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformXPointerSetExpr", xmlSecTransformGetName(transform));
            goto done;

        }
    } else {
        /* Visa3D protocol doesn't follow XML/XPointer/XMLDSig specs
         * and allows invalid XPointer expressions (e.g. "#12345") in
         * the URI attribute.
         * Since we couldn't evaluate such expressions thru XPath/XPointer
         * engine, we need to have this hack here
         */
        xmlSecTransformPtr transform;

        transform = xmlSecTransformCtxCreateAndPrepend(ctx, xmlSecTransformVisa3DHackId);
        if(!xmlSecTransformIsValid(transform)) {
            xmlSecInternalError("xmlSecTransformCtxCreateAndPrepend(xmlSecTransformVisa3DHackId)", NULL);
            goto done;
        }

        ret = xmlSecTransformVisa3DHackSetID(transform, xptr);
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformVisa3DHackSetID", xmlSecTransformGetName(transform));
            goto done;
        }
    }

    /* success */
    res = 0;

done:
    if(buf != NULL) {
        xmlFree(buf);
    }
    return(res);
}

/**
 * @brief Prepares the transform context for processing data.
 * @details Prepares the transform context for processing data of @p inputDataType.
 * @param ctx the pointer to transforms chain processing context.
 * @param inputDataType the expected input type.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecTransformCtxPrepare(xmlSecTransformCtxPtr ctx, xmlSecTransformDataType inputDataType) {
    xmlSecTransformDataType firstType;
    xmlSecTransformPtr transform;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->result == NULL, -1);
    xmlSecAssert2(ctx->status == xmlSecTransformStatusNone, -1);

    /* add binary buffer to store result */
    transform = xmlSecTransformCtxCreateAndAppend(ctx, xmlSecTransformMemBufId);
    if(!xmlSecTransformIsValid(transform)) {
        xmlSecInternalError("xmlSecTransformCtxCreateAndAppend(xmlSecTransformMemBufId)", NULL);
        return(-1);
    }
    ctx->result = xmlSecTransformMemBufGetBuffer(transform);
    if(ctx->result == NULL) {
        xmlSecInternalError("xmlSecTransformMemBufGetBuffer(xmlSecTransformMemBufId)",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    firstType = xmlSecTransformGetDataType(ctx->first, xmlSecTransformModePush, ctx);
    if(((firstType & xmlSecTransformDataTypeBin) == 0) &&
       ((inputDataType & xmlSecTransformDataTypeBin) != 0)) {

        /* need to add parser transform */
        transform = xmlSecTransformCtxCreateAndPrepend(ctx, xmlSecTransformXmlParserId);
        if(transform == NULL) {
            xmlSecInternalError("xmlSecTransformCtxCreateAndPrepend(xmlSecTransformXmlParserId)", NULL);
            return(-1);
        }
    } else if(((firstType & xmlSecTransformDataTypeXml) == 0) &&
       ((inputDataType & xmlSecTransformDataTypeXml) != 0)) {

        /* need to add c14n transform */
        transform = xmlSecTransformCtxCreateAndPrepend(ctx, xmlSecTransformInclC14NId);
        if(transform == NULL) {
            xmlSecInternalError("xmlSecTransformCtxCreateAndPrepend(xmlSecTransformInclC14NId)", NULL);
            return(-1);
        }
    }

    /* finally let application a chance to verify that it's ok to execute
     * this transforms chain */
    if(ctx->preExecCallback != NULL) {
        ret = (ctx->preExecCallback)(ctx);
        if(ret < 0) {
            xmlSecInternalError("ctx->preExecCallback", NULL);
            return(-1);
        }
    }

    ctx->status = xmlSecTransformStatusWorking;
    return(0);
}

/**
 * @brief Processes binary data using transforms chain in @p ctx.
 * @details Processes binary data using transforms chain in the @p ctx.
 * @param ctx the pointer to transforms chain processing context.
 * @param data the input binary data buffer.
 * @param dataSize the input data size.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecTransformCtxBinaryExecute(xmlSecTransformCtxPtr ctx,
                                const xmlSecByte* data, xmlSecSize dataSize) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->result == NULL, -1);
    xmlSecAssert2(ctx->status == xmlSecTransformStatusNone, -1);

    /* we should not have uri stored in ctx */
    xmlSecAssert2(ctx->uri == NULL, -1);

    ret = xmlSecTransformCtxPrepare(ctx, xmlSecTransformDataTypeBin);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformCtxPrepare(TypeBin)", NULL);
        return(-1);
    }

    ret = xmlSecTransformPushBin(ctx->first, data, dataSize, 1, ctx);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecTransformPushBin", NULL,
                             "dataSize=" XMLSEC_SIZE_FMT,  dataSize);
        return(-1);
    }

    ctx->status = xmlSecTransformStatusFinished;
    return(0);
}

/**
 * @brief Processes binary data from URI using transforms chain in @p ctx.
 * @details Process binary data from the URI using transforms chain in @p ctx.
 * @param ctx the pointer to transforms chain processing context.
 * @param uri the URI.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecTransformCtxUriExecute(xmlSecTransformCtxPtr ctx, const xmlChar* uri) {
    xmlSecTransformPtr uriTransform;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->status == xmlSecTransformStatusNone, -1);
    xmlSecAssert2(uri != NULL, -1);

    /* we should not execute transform for a different uri */
    xmlSecAssert2((ctx->uri == NULL) || (uri == ctx->uri) || xmlStrEqual(uri, ctx->uri), -1);

    uriTransform = xmlSecTransformCtxCreateAndPrepend(ctx, xmlSecTransformInputURIId);
    if(uriTransform == NULL) {
        xmlSecInternalError("xmlSecTransformCtxCreateAndPrepend(xmlSecTransformInputURIId)", NULL);
        return(-1);
    }

    ret = xmlSecTransformInputURIOpen(uriTransform, uri);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecTransformInputURIOpen", NULL,
                            "uri=%s", xmlSecErrorsSafeString(uri));
        return(-1);
    }

    /* we do not need to do something special for this transform */
    ret = xmlSecTransformCtxPrepare(ctx, xmlSecTransformDataTypeUnknown);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformCtxPrepare(TypeUnknown)", NULL);
        return(-1);
    }

    /* Now we have a choice: we either can push from first transform or pop
     * from last. Our C14N transforms prefers push, so push data!
     */
    ret = xmlSecTransformPump(uriTransform, uriTransform->next, ctx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPump",
                            xmlSecTransformGetName(uriTransform));
        return(-1);
    }

    /* Close to free up file handle */
    ret = xmlSecTransformInputURIClose(uriTransform);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformInputURIClose",
                            xmlSecTransformGetName(uriTransform));
        return(-1);
    }

    /* Done */
    ctx->status = xmlSecTransformStatusFinished;
    return(0);
}

/**
 * @brief Processes nodes using transforms chain in @p ctx.
 * @details Process @p nodes using transforms in the transforms chain in @p ctx.
 * @param ctx the pointer to transforms chain processing context.
 * @param nodes the input node set.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecTransformCtxXmlExecute(xmlSecTransformCtxPtr ctx, xmlSecNodeSetPtr nodes) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->result == NULL, -1);
    xmlSecAssert2(ctx->status == xmlSecTransformStatusNone, -1);
    xmlSecAssert2(nodes != NULL, -1);

    xmlSecAssert2((ctx->uri == NULL) || (xmlStrlen(ctx->uri) == 0), -1);

    ret = xmlSecTransformCtxPrepare(ctx, xmlSecTransformDataTypeXml);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformCtxPrepare(TypeXml)", NULL);
        return(-1);
    }

    /* it's better to do push than pop because all XML transform
     * just don't care and c14n likes push more than pop */
    ret = xmlSecTransformPushXml(ctx->first, nodes, ctx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPushXml",
                            xmlSecTransformGetName(ctx->first));
        return(-1);
    }

    ctx->status = xmlSecTransformStatusFinished;
    return(0);
}

/**
 * @brief Executes transforms chain in @p ctx.
 * @param ctx the pointer to transforms chain processing context.
 * @param doc the pointer to input document.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecTransformCtxExecute(xmlSecTransformCtxPtr ctx, xmlDocPtr doc) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->result == NULL, -1);
    xmlSecAssert2(ctx->status == xmlSecTransformStatusNone, -1);
    xmlSecAssert2(doc != NULL, -1);

    if((ctx->uri == NULL) || (xmlSecStrlen(ctx->uri) == 0)) {
        xmlSecNodeSetPtr nodes;

        if((ctx->xptrExpr != NULL) && (xmlSecStrlen(ctx->xptrExpr) > 0)){
            /* our xpointer transform takes care of providing correct nodes set */
            nodes = xmlSecNodeSetCreate(doc, NULL, xmlSecNodeSetNormal);
            if(nodes == NULL) {
                xmlSecInternalError("xmlSecNodeSetCreate", NULL);
                return(-1);
            }

        } else {
            /* we do not want to have comments for empty URI */
            nodes = xmlSecNodeSetGetChildren(doc, NULL, 0, 0);
            if(nodes == NULL) {
                xmlSecInternalError("xmlSecNodeSetGetChildren", NULL);
                return(-1);
            }
        }
        ret = xmlSecTransformCtxXmlExecute(ctx, nodes);
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformCtxXmlExecute", NULL);
            xmlSecNodeSetDestroy(nodes);
            return(-1);
        }
        /* TODO: don't destroy nodes here */
        xmlSecNodeSetDestroy(nodes);
    } else {
        ret = xmlSecTransformCtxUriExecute(ctx, ctx->uri);
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformCtxUriExecute", NULL);
            return(-1);
        }
    }

    return(0);
}

/**
 * @brief Prints transforms context debug information to @p output.
 * @details Prints transforms context debug information to @p output.
 * @param ctx the pointer to transforms chain processing context.
 * @param output the pointer to output FILE.
 */
void
xmlSecTransformCtxDebugDump(xmlSecTransformCtxPtr ctx, FILE* output) {
    xmlSecTransformPtr transform;

    xmlSecAssert(ctx != NULL);
    xmlSecAssert(output != NULL);

    fprintf(output, "== TRANSFORMS CTX (status=" XMLSEC_ENUM_FMT ")\n",
        XMLSEC_ENUM_CAST(ctx->status));

    fprintf(output, "== flags: 0x%08x\n", ctx->flags);
    fprintf(output, "== flags2: 0x%08x\n", ctx->flags2);
    if(xmlSecPtrListGetSize(&(ctx->enabledTransforms)) > 0) {
        fprintf(output, "== enabled transforms: ");
        xmlSecTransformIdListDebugDump(&(ctx->enabledTransforms), output);
    } else {
        fprintf(output, "== enabled transforms: all\n");
    }

    fprintf(output, "=== uri: %s\n",
            (ctx->uri != NULL) ? ctx->uri : BAD_CAST "NULL");
    fprintf(output, "=== uri xpointer expr: %s\n",
            (ctx->xptrExpr != NULL) ? ctx->xptrExpr : BAD_CAST "NULL");
    for(transform = ctx->first; transform != NULL; transform = transform->next) {
        xmlSecTransformDebugDump(transform, output);
    }
}

/**
 * @brief Prints transforms context debug information to @p output in XML format.
 * @details Prints transforms context debug information to @p output in XML format.
 * @param ctx the pointer to transforms chain processing context.
 * @param output the pointer to output FILE.
 */
void
xmlSecTransformCtxDebugXmlDump(xmlSecTransformCtxPtr ctx, FILE* output) {
    xmlSecTransformPtr transform;

    xmlSecAssert(ctx != NULL);
    xmlSecAssert(output != NULL);

    fprintf(output, "<TransformCtx status=\"" XMLSEC_ENUM_FMT "\">\n",
        XMLSEC_ENUM_CAST(ctx->status));

    fprintf(output, "<Flags>%08x</Flags>\n", ctx->flags);
    fprintf(output, "<Flags2>%08x</Flags2>\n", ctx->flags2);
    if(xmlSecPtrListGetSize(&(ctx->enabledTransforms)) > 0) {
        fprintf(output, "<EnabledTransforms>\n");
        xmlSecTransformIdListDebugXmlDump(&(ctx->enabledTransforms), output);
        fprintf(output, "</EnabledTransforms>\n");
    } else {
        fprintf(output, "<EnabledTransforms>all</EnabledTransforms>\n");
    }


    fprintf(output, "<Uri>");
    xmlSecPrintXmlString(output, ctx->uri);
    fprintf(output, "</Uri>\n");

    fprintf(output, "<UriXPointer>");
    xmlSecPrintXmlString(output, ctx->xptrExpr);
    fprintf(output, "</UriXPointer>\n");

    for(transform = ctx->first; transform != NULL; transform = transform->next) {
        xmlSecTransformDebugXmlDump(transform, output);
    }
    fprintf(output, "</TransformCtx>\n");
}

/******************************************************************************
 *
 * xmlSecTransform
 *
  *****************************************************************************/
/**
 * @brief Creates a new transform of the specified klass.
 * @details Creates new transform of the @p id klass. The caller is responsible for
 * destroying returned transform using #xmlSecTransformDestroy function.
 * @param id the transform id to create.
 *
 * @return pointer to newly created transform or NULL if an error occurs.
 */
xmlSecTransformPtr
xmlSecTransformCreate(xmlSecTransformId id) {
    xmlSecTransformPtr transform;
    int ret;

    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->klassSize >= sizeof(xmlSecTransformKlass), NULL);
    xmlSecAssert2(id->objSize >= sizeof(xmlSecTransform), NULL);
    xmlSecAssert2(id->name != NULL, NULL);

    /* Allocate a new xmlSecTransform and fill the fields. */
    transform = (xmlSecTransformPtr)xmlMalloc(id->objSize);
    if(transform == NULL) {
        xmlSecMallocError(id->objSize, NULL);
        return(NULL);
    }
    memset(transform, 0, id->objSize);
    transform->id = id;

    if(id->initialize != NULL) {
        ret = (id->initialize)(transform);
        if(ret < 0) {
            xmlSecInternalError("id->initialize",
                                xmlSecTransformGetName(transform));
            xmlSecTransformDestroy(transform);
            return(NULL);
        }
    }

    ret = xmlSecBufferInitialize(&(transform->inBuf), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize",
                            xmlSecTransformGetName(transform));
        xmlSecTransformDestroy(transform);
        return(NULL);
    }

    ret = xmlSecBufferInitialize(&(transform->outBuf), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize",
                            xmlSecTransformGetName(transform));
        xmlSecTransformDestroy(transform);
        return(NULL);
    }

    return(transform);
}

/**
 * @brief Destroys a transform object.
 * @details Destroys transform created with #xmlSecTransformCreate function.
 * @param transform the pointer to transform.
 */
void
xmlSecTransformDestroy(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformIsValid(transform));
    xmlSecAssert(transform->id->objSize > 0);

    /* first need to remove ourselves from chain */
    xmlSecTransformRemove(transform);

    xmlSecBufferFinalize(&(transform->inBuf));
    xmlSecBufferFinalize(&(transform->outBuf));

    /* we never destroy input nodes, output nodes
     * are destroyed if and only if they are different
     * from input nodes
     */
    if((transform->outNodes != NULL) && (transform->outNodes != transform->inNodes)) {
        xmlSecNodeSetDestroy(transform->outNodes);
    }
    if(transform->id->finalize != NULL) {
        (transform->id->finalize)(transform);
    }
    memset(transform, 0, transform->id->objSize);
    xmlFree(transform);
}

/**
 * @brief Reads a transform from a node.
 * @details Reads transform from the @p node as follows:
 *
 *    1) reads "Algorithm" attribute;
 *
 *    2) checks the lists of known and allowed transforms;
 *
 *    3) calls transform's create method;
 *
 *    4) calls transform's read transform node method.
 * @param node the pointer to the transform's node.
 * @param usage the transform usage (signature, encryption, ...).
 * @param transformCtx the transform's chain processing context.
 *
 * @return pointer to newly created transform or NULL if an error occurs.
 */
xmlSecTransformPtr
xmlSecTransformNodeRead(xmlNodePtr node, xmlSecTransformUsage usage, xmlSecTransformCtxPtr transformCtx) {
    xmlSecTransformPtr transform;
    xmlSecTransformId id;
    xmlChar *href;
    int ret;

    xmlSecAssert2(node != NULL, NULL);
    xmlSecAssert2(transformCtx != NULL, NULL);

    href = xmlGetProp(node, xmlSecAttrAlgorithm);
    if(href == NULL) {
        xmlSecInvalidNodeAttributeError(node, xmlSecAttrAlgorithm,
                                        NULL, "empty");
        return(NULL);
    }

    id = xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), href, usage);
    if(id == xmlSecTransformIdUnknown) {
        xmlSecInternalError2("xmlSecTransformIdListFindByHref", NULL,
                             "href=%s", xmlSecErrorsSafeString(href));
        xmlFree(href);
        return(NULL);
    }

    /* check with enabled transforms list */
    if((xmlSecPtrListGetSize(&(transformCtx->enabledTransforms)) > 0) &&
       (xmlSecTransformIdListFind(&(transformCtx->enabledTransforms), id) != 1)) {
        xmlSecOtherError2(XMLSEC_ERRORS_R_TRANSFORM_DISABLED,
                          xmlSecTransformKlassGetName(id),
                          "href=%s", xmlSecErrorsSafeString(href));
        xmlFree(href);
        return(NULL);
    }

    transform = xmlSecTransformCreate(id);
    if(!xmlSecTransformIsValid(transform)) {
        xmlSecInternalError("xmlSecTransformCreate(id)",
                            xmlSecTransformKlassGetName(id));
        xmlFree(href);
        return(NULL);
    }

    if(transform->id->readNode != NULL) {
        ret = transform->id->readNode(transform, node, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("readNode",
                                xmlSecTransformGetName(transform));
            xmlSecTransformDestroy(transform);
            xmlFree(href);
            return(NULL);
        }
    }

    /* finally remember the transform node */
    transform->hereNode = node;
    xmlFree(href);
    return(transform);
}

/**
 * @brief Pops data from left transform and pushes to right transform.
 * @details Pops data from @p left transform and pushes to @p right transform until
 * no more data is available.
 * @param left the source pumping transform.
 * @param right the destination pumping transform.
 * @param transformCtx the transform's chain processing context.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformPump(xmlSecTransformPtr left, xmlSecTransformPtr right, xmlSecTransformCtxPtr transformCtx) {
    xmlSecTransformDataType leftType;
    xmlSecTransformDataType rightType;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(left), -1);
    xmlSecAssert2(xmlSecTransformIsValid(right), -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    xmlSecAssert2(transformCtx->binaryChunkSize > 0, -1);

    leftType = xmlSecTransformGetDataType(left, xmlSecTransformModePop, transformCtx);
    rightType = xmlSecTransformGetDataType(right, xmlSecTransformModePush, transformCtx);

    if(((leftType & xmlSecTransformDataTypeXml) != 0) &&
       ((rightType & xmlSecTransformDataTypeXml) != 0)) {

       xmlSecNodeSetPtr nodes = NULL;

       ret = xmlSecTransformPopXml(left, &nodes, transformCtx);
       if(ret < 0) {
            xmlSecInternalError("xmlSecTransformPopXml",
                                xmlSecTransformGetName(left));
            return(-1);
       }

       ret = xmlSecTransformPushXml(right, nodes, transformCtx);
       if(ret < 0) {
            xmlSecInternalError("xmlSecTransformPushXml",
                                xmlSecTransformGetName(right));
            return(-1);
       }
    }  else if(((leftType & xmlSecTransformDataTypeBin) != 0) &&
               ((rightType & xmlSecTransformDataTypeBin) != 0)) {
        xmlSecByte* buf;
        int final = 0;

        buf = xmlMalloc(transformCtx->binaryChunkSize);
        if(buf == NULL) {
            xmlSecMallocError(transformCtx->binaryChunkSize, NULL);
            return(-1);
        }

        do {
            xmlSecSize bufSize = 0;
            ret = xmlSecTransformPopBin(left, buf, transformCtx->binaryChunkSize, &bufSize, transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecTransformPopBin", xmlSecTransformGetName(left));
                xmlFree(buf);
                return(-1);
            }
            final = (bufSize == 0) ? 1 : 0;
            ret = xmlSecTransformPushBin(right, buf, bufSize, final, transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecTransformPushBin", xmlSecTransformGetName(right));
                xmlFree(buf);
                return(-1);
            }
        } while(final == 0);

        xmlFree(buf);
    } else {
        xmlSecInvalidTransfromError2(left,
                    "transforms input/output data formats do not match, right transform=\"%s\"",
                    xmlSecErrorsSafeString(xmlSecTransformGetName(right)));
    }
    return(0);
}


/**
 * @brief Sets the transform's key.
 * @param transform the pointer to transform.
 * @param key the pointer to key.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecTransformSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(key != NULL, -1);

    if(transform->id->setKey != NULL) {
        return((transform->id->setKey)(transform, key));
    }
    return(0);
}

/**
 * @brief Sets the key requirements for @p transform in @p keyReq.
 * @details Sets the key requirements for @p transform in the @p keyReq.
 * @param transform the pointer to transform.
 * @param keyReq the pointer to keys requirements object.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecTransformSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId       = xmlSecKeyDataIdUnknown;
    keyReq->keyType     = xmlSecKeyDataTypeUnknown;
    keyReq->keyUsage    = xmlSecKeyUsageAny;
    keyReq->keyBitsSize = 0;

    if(transform->id->setKeyReq != NULL) {
        return((transform->id->setKeyReq)(transform, keyReq));
    }
    return(0);
}

/**
 * @brief Verifies data against the transform's processing results.
 * @details Verifies the data with transform's processing results
 * (for digest, HMAC and signature transforms). The verification
 * result is stored in the @p status member of xmlSecTransform object.
 * @param transform the pointer to transform.
 * @param data the binary data for verification.
 * @param dataSize the data size.
 * @param transformCtx the transform's chain processing context.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformVerify(xmlSecTransformPtr transform, const xmlSecByte* data,
                    xmlSecSize dataSize, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->id->verify != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    return((transform->id->verify)(transform, data, dataSize, transformCtx));
}

/**
 * @brief Verifies binary results from base64-decoded node content.
 * @details Gets the @p node content, base64 decodes it and calls #xmlSecTransformVerify
 * function to verify binary results.
 * @param transform the pointer to transform.
 * @param node the pointer to node.
 * @param transformCtx the transform's chain processing context.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformVerifyNodeContent(xmlSecTransformPtr transform, xmlNodePtr node,
                                 xmlSecTransformCtxPtr transformCtx) {
    xmlSecBuffer buffer;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ret = xmlSecBufferInitialize(&buffer, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecBufferBase64NodeContentRead(&buffer, node);
    if((ret < 0) || (xmlSecBufferGetData(&buffer) == NULL)) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentRead",
                            xmlSecTransformGetName(transform));
        xmlSecBufferFinalize(&buffer);
        return(-1);
    }

    ret = xmlSecTransformVerify(transform, xmlSecBufferGetData(&buffer),
                                xmlSecBufferGetSize(&buffer), transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformVerify",
                            xmlSecTransformGetName(transform));
        xmlSecBufferFinalize(&buffer);
        return(-1);
    }

    xmlSecBufferFinalize(&buffer);
    return(0);
}

/**
 * @brief Gets transform input or output data type (binary or XML).
 * @details Gets transform input (@p mode is "push") or output (@p mode is "pop") data
 * type (binary or XML).
 * @param transform the pointer to transform.
 * @param mode the data mode (push or pop).
 * @param transformCtx the transform's chain processing context.
 *
 * @return the transform's data type for the @p mode operation.
 */
xmlSecTransformDataType
xmlSecTransformGetDataType(xmlSecTransformPtr transform, xmlSecTransformMode mode,
                    xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), xmlSecTransformDataTypeUnknown);
    xmlSecAssert2(transform->id->getDataType != NULL, xmlSecTransformDataTypeUnknown);

    return((transform->id->getDataType)(transform, mode, transformCtx));
}

/**
 * @brief Processes binary data and pushes results to next transform.
 * @details Process binary @p data and pushes results to next transform.
 * @param transform the pointer to transform object.
 * @param data the input binary data,
 * @param dataSize the input data size.
 * @param final the flag: if set to 1 then it's the last
 *                      data chunk.
 * @param transformCtx the pointer to transform context object.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformPushBin(xmlSecTransformPtr transform, const xmlSecByte* data,
                    xmlSecSize dataSize, int final, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->id->pushBin != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    return((transform->id->pushBin)(transform, data, dataSize, final, transformCtx));
}

/**
 * @brief Pops data from previous transform, processes it, and returns result.
 * @details Pops data from previous transform in the chain, processes data and
 * returns result in the @p data buffer. The size of returned data is
 * placed in the @p dataSize.
 * @param transform the pointer to transform object.
 * @param data the buffer to store result data.
 * @param maxDataSize the size of the buffer @p data.
 * @param dataSize the pointer to returned data size.
 * @param transformCtx the pointer to transform context object.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformPopBin(xmlSecTransformPtr transform, xmlSecByte* data,
                    xmlSecSize maxDataSize, xmlSecSize* dataSize, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->id->popBin != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    return((transform->id->popBin)(transform, data, maxDataSize, dataSize, transformCtx));
}

/**
 * @brief Processes nodes and pushes result to the next transform.
 * @details Processes @p nodes and pushes result to the next transform in the chain.
 * @param transform the pointer to transform object.
 * @param nodes the input nodes.
 * @param transformCtx the pointer to transform context object.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformPushXml(xmlSecTransformPtr transform, xmlSecNodeSetPtr nodes,
                    xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->id->pushXml != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    return((transform->id->pushXml)(transform, nodes, transformCtx));
}

/**
 * @brief Pops data from previous transform, processes it, and returns nodes.
 * @details Pops data from previous transform in the chain, processes the data and
 * returns result in @p nodes.
 * @param transform the pointer to transform object.
 * @param nodes the pointer to store popinter to result nodes.
 * @param transformCtx the pointer to transform context object.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformPopXml(xmlSecTransformPtr transform, xmlSecNodeSetPtr* nodes,
                    xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->id->popXml != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    return((transform->id->popXml)(transform, nodes, transformCtx));
}

/**
 * @brief Executes a transform (used by default push/pop methods).
 * @details Executes transform (used by default popBin/pushBin/popXml/pushXml methods).
 * @param transform the pointer to transform.
 * @param last the flag: if set to 1 then it's the last data chunk.
 * @param transformCtx the transform's chain processing context.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->id->execute != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    return((transform->id->execute)(transform, last, transformCtx));
}

/**
 * @brief Prints transform's debug information to @p output.
 * @param transform the pointer to transform.
 * @param output the pointer to output FILE.
 */
void
xmlSecTransformDebugDump(xmlSecTransformPtr transform, FILE* output) {
    xmlSecAssert(xmlSecTransformIsValid(transform));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== Transform: %s (href=%s)\n",
                xmlSecErrorsSafeString(transform->id->name),
                xmlSecErrorsSafeString(transform->id->href));
}

/**
 * @brief Prints transform's debug information to @p output in XML format.
 * @details Prints transform's debug information to @p output in XML format.
 * @param transform the pointer to transform.
 * @param output the pointer to output FILE.
 */
void
xmlSecTransformDebugXmlDump(xmlSecTransformPtr transform, FILE* output) {
    xmlSecAssert(xmlSecTransformIsValid(transform));
    xmlSecAssert(output != NULL);

    fprintf(output, "<Transform name=\"");
    xmlSecPrintXmlString(output,transform->id->name);
    fprintf(output, "\" href=\"");
    xmlSecPrintXmlString(output, transform->id->href);
    fprintf(output, "\" />\n");
}

/******************************************************************************
 *
 * Operations on transforms chain
 *
  *****************************************************************************/
/**
 * @brief Connects two transforms in the chain, inserting a conversion if needed.
 * @details If the data object is a node-set and the next transform requires octets,
 * the signature application MUST attempt to convert the node-set to an octet
 * stream using Canonical XML [XML-C14N].
 *
 * The story is different if the right transform is base64 decode
 * (http://www.w3.org/TR/xmldsig-core/#sec-Base-64):
 *
 * This transform requires an octet stream for input. If an XPath node-set
 * (or sufficiently functional alternative) is given as input, then it is
 * converted to an octet stream by performing operations logically equivalent
 * to 1) applying an XPath transform with expression self::text(), then 2)
 * taking the string-value of the node-set. Thus, if an XML element is
 * identified by a barename XPointer in the Reference URI, and its content
 * consists solely of base64 encoded character data, then this transform
 * automatically strips away the start and end tags of the identified element
 * and any of its descendant elements as well as any descendant comments and
 * processing instructions. The output of this transform is an octet stream.
 * @param left the pointer to left (prev) transform.
 * @param right the pointer to right (next) transform.
 * @param transformCtx the transform's chain processing context.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformConnect(xmlSecTransformPtr left, xmlSecTransformPtr right,
                       xmlSecTransformCtxPtr transformCtx) {
    xmlSecTransformDataType leftType;
    xmlSecTransformDataType rightType;
    xmlSecTransformId middleId;
    xmlSecTransformPtr middle;

    xmlSecAssert2(xmlSecTransformIsValid(left), -1);
    xmlSecAssert2(xmlSecTransformIsValid(right), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    leftType = xmlSecTransformGetDataType(left, xmlSecTransformModePop, transformCtx);
    rightType = xmlSecTransformGetDataType(right, xmlSecTransformModePush, transformCtx);

    /* happy case first: nothing need to be done */
    if((((leftType & xmlSecTransformDataTypeBin) != 0) &&
        ((rightType & xmlSecTransformDataTypeBin) != 0)) ||
       (((leftType & xmlSecTransformDataTypeXml) != 0) &&
        ((rightType & xmlSecTransformDataTypeXml) != 0))) {

        left->next = right;
        right->prev = left;
        return(0);
    }

    if(((leftType & xmlSecTransformDataTypeBin) != 0) &&
        ((rightType & xmlSecTransformDataTypeXml) != 0)) {

        /* need to insert parser */
        middleId = xmlSecTransformXmlParserId;
    } else if(((leftType & xmlSecTransformDataTypeXml) != 0) &&
        ((rightType & xmlSecTransformDataTypeBin) != 0)) {

        /* need to insert c14n or special pre-base64 transform */
        if(xmlSecTransformCheckId(right, xmlSecTransformBase64Id)) {
            middleId = xmlSecTransformRemoveXmlTagsC14NId;
        } else {
            middleId = xmlSecTransformInclC14NId;
        }
    } else {
        xmlSecInvalidTransfromError2(left,
                    "transforms types do not match, right transform=\"%s\"",
                    xmlSecErrorsSafeString(xmlSecTransformGetName(right)));
        return(-1);
    }

    /* insert transform */
    middle = xmlSecTransformCreate(middleId);
    if(middle == NULL) {
        xmlSecInternalError("xmlSecTransformCreate",
                            xmlSecTransformKlassGetName(middleId));
        return(-1);
    }
    left->next = middle;
    middle->prev = left;
    middle->next = right;
    right->prev = middle;
    return(0);
}

/**
 * @brief Removes @p transform from the chain.
 * @param transform the pointer to xmlSecTransform structure.
 */
void
xmlSecTransformRemove(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformIsValid(transform));

    if(transform->next != NULL) {
        transform->next->prev = transform->prev;
    }
    if(transform->prev != NULL) {
        transform->prev->next = transform->next;
    }
    transform->next = transform->prev = NULL;
}


/******************************************************************************
 *
 * Default callbacks, most of the transforms can use them
 *
  *****************************************************************************/
/**
 * @brief Gets transform data type by analyzing available push/pop methods.
 * @details Gets transform input (@p mode is "push") or output (@p mode is "pop") data
 * type (binary or XML) by analyzing available pushBin/popBin/pushXml/popXml
 * methods.
 * @param transform the pointer to transform.
 * @param mode the data mode (push or pop).
 * @param transformCtx the transform's chain processing context.
 *
 * @return the transform's data type for the @p mode operation.
 */
xmlSecTransformDataType
xmlSecTransformDefaultGetDataType(xmlSecTransformPtr transform, xmlSecTransformMode mode,
                                  xmlSecTransformCtxPtr transformCtx) {
    xmlSecTransformDataType type = xmlSecTransformDataTypeUnknown;

    xmlSecAssert2(xmlSecTransformIsValid(transform), xmlSecTransformDataTypeUnknown);
    xmlSecAssert2(transformCtx != NULL, xmlSecTransformDataTypeUnknown);

    /* we'll try to guess the data type based on the handlers we have */
    switch(mode) {
        case xmlSecTransformModePush:
            if(transform->id->pushBin != NULL) {
                type |= xmlSecTransformDataTypeBin;
            }
            if(transform->id->pushXml != NULL) {
                type |= xmlSecTransformDataTypeXml;
            }
            break;
        case xmlSecTransformModePop:
            if(transform->id->popBin != NULL) {
                type |= xmlSecTransformDataTypeBin;
            }
            if(transform->id->popXml != NULL) {
                type |= xmlSecTransformDataTypeXml;
            }
            break;
        default:
            xmlSecUnsupportedEnumValueError("mode", mode, xmlSecTransformGetName(transform));
            return(xmlSecTransformDataTypeUnknown);
    }

    return(type);
}

/**
 * @brief Processes binary data via execute method and pushes results.
 * @details Process binary @p data by calling transform's execute method and pushes
 * results to next transform.
 * @param transform the pointer to transform object.
 * @param data the input binary data,
 * @param dataSize the input data size.
 * @param final the flag: if set to 1 then it's the last
 *                      data chunk.
 * @param transformCtx the pointer to transform context object.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformDefaultPushBin(xmlSecTransformPtr transform, const xmlSecByte* data,
                        xmlSecSize dataSize, int final, xmlSecTransformCtxPtr transformCtx) {
    xmlSecSize inSize = 0;
    xmlSecSize outSize = 0;
    int finalData = 0;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    do {
        /* append data to input buffer */
        if(dataSize > 0) {
            xmlSecSize chunkSize;

            xmlSecAssert2(data != NULL, -1);

            chunkSize = dataSize;
            if(chunkSize > transformCtx->binaryChunkSize) {
                chunkSize = transformCtx->binaryChunkSize;
            }

            ret = xmlSecBufferAppend(&(transform->inBuf), data, chunkSize);
            if(ret < 0) {
                xmlSecInternalError2("xmlSecBufferAppend", xmlSecTransformGetName(transform),
                    "size=" XMLSEC_SIZE_FMT, chunkSize);
                return(-1);
            }

            dataSize -= chunkSize;
            data += chunkSize;
        }

        /* process data */
        finalData = (((dataSize == 0) && (final != 0)) ? 1 : 0);
        ret = xmlSecTransformExecute(transform, finalData, transformCtx);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecTransformExecute", xmlSecTransformGetName(transform),
                "final=%d", final);
            return(-1);
        }

        /* push data to the next transform */
        inSize = xmlSecBufferGetSize(&(transform->inBuf));
        outSize = xmlSecBufferGetSize(&(transform->outBuf));
        if(inSize > 0) {
            finalData = 0;
        }

        /* we don't want to push too much */
        if(outSize > transformCtx->binaryChunkSize) {
            outSize = transformCtx->binaryChunkSize;
            finalData = 0;
        }
        if((transform->next != NULL) && ((outSize > 0) || (finalData != 0))) {
            ret = xmlSecTransformPushBin(transform->next,
                            xmlSecBufferGetData(&(transform->outBuf)),
                            outSize,
                            finalData,
                            transformCtx);
            if(ret < 0) {
                xmlSecInternalError3("xmlSecTransformPushBin", xmlSecTransformGetName(transform->next),
                    "final=%d;outSize=" XMLSEC_SIZE_FMT, final, outSize);
                return(-1);
            }
        }

        /* remove data anyway */
        if(outSize > 0){
            ret = xmlSecBufferRemoveHead(&(transform->outBuf), outSize);
            if(ret < 0) {
                xmlSecInternalError2("xmlSecBufferRemoveHead", xmlSecTransformGetName(transform),
                    "size=" XMLSEC_SIZE_FMT, outSize);
                return(-1);
            }
        }
    } while((dataSize > 0) || (outSize > 0));

    return(0);
}

/**
 * @brief Pops and processes data via execute method, returns result.
 * @details Pops data from previous transform in the chain, processes data by calling
 * transform's execute method and returns result in the @p data buffer. The
 * size of returned data is placed in the @p dataSize.
 * @param transform the pointer to transform object.
 * @param data the buffer to store result data.
 * @param maxDataSize the size of the buffer @p data.
 * @param dataSize the pointer to returned data size.
 * @param transformCtx the pointer to transform context object.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformDefaultPopBin(xmlSecTransformPtr transform, xmlSecByte* data,
                             xmlSecSize maxDataSize, xmlSecSize* dataSize,
                             xmlSecTransformCtxPtr transformCtx) {
    xmlSecSize outSize;
    int final = 0;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    while((xmlSecBufferGetSize(&(transform->outBuf)) == 0) && (final == 0)) {
        /* read data from previous transform if exist */
        if(transform->prev != NULL) {
            xmlSecSize inSize, chunkSize;

            inSize = xmlSecBufferGetSize(&(transform->inBuf));
            chunkSize = transformCtx->binaryChunkSize;

            /* ensure that we have space for at least one data chunk */
            ret = xmlSecBufferSetMaxSize(&(transform->inBuf), inSize + chunkSize);
            if(ret < 0) {
                xmlSecInternalError2("xmlSecBufferSetMaxSize", xmlSecTransformGetName(transform),
                    "size=" XMLSEC_SIZE_FMT, (inSize + chunkSize));
                return(-1);
            }

            /* get data from previous transform */
            ret = xmlSecTransformPopBin(transform->prev,
                            xmlSecBufferGetData(&(transform->inBuf)) + inSize,
                            chunkSize, &chunkSize, transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecTransformPopBin", xmlSecTransformGetName(transform->prev));
                return(-1);
            }

            /* adjust our size if needed */
            if(chunkSize > 0) {
                ret = xmlSecBufferSetSize(&(transform->inBuf), inSize + chunkSize);
                if(ret < 0) {
                    xmlSecInternalError2("xmlSecBufferSetSize", xmlSecTransformGetName(transform),
                        "size=" XMLSEC_SIZE_FMT, (inSize + chunkSize));
                    return(-1);
                }
                final = 0; /* the previous transform returned some data..*/
            } else {
                final = 1; /* no data returned from previous transform, we are done */
            }
        } else {
            final = 1; /* no previous transform, we are "permanently final" */
        }

        /* execute our transform */
        ret = xmlSecTransformExecute(transform, final, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformExecute",
                                xmlSecTransformGetName(transform));
            return(-1);
        }
    }

    /* copy result (if any) */
    outSize = xmlSecBufferGetSize(&(transform->outBuf));
    if(outSize > maxDataSize) {
        outSize = maxDataSize;
    }

    /* we don't want to put too much */
    if(outSize > transformCtx->binaryChunkSize) {
        outSize = transformCtx->binaryChunkSize;
    }
    if(outSize > 0) {
        xmlSecAssert2(xmlSecBufferGetData(&(transform->outBuf)), -1);

        memcpy(data, xmlSecBufferGetData(&(transform->outBuf)), outSize);

        ret = xmlSecBufferRemoveHead(&(transform->outBuf), outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead",
                                 xmlSecTransformGetName(transform),
                                 "size=" XMLSEC_SIZE_FMT, outSize);
            return(-1);
        }
    }

    /* set the result size */
    (*dataSize) = outSize;
    return(0);
}

/**
 * @brief Processes nodes via execute method and pushes result.
 * @details Processes @p nodes by calling transform's execute method and pushes
 * result to the next transform in the chain.
 * @param transform the pointer to transform object.
 * @param nodes the input nodes.
 * @param transformCtx the pointer to transform context object.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformDefaultPushXml(xmlSecTransformPtr transform, xmlSecNodeSetPtr nodes,
                            xmlSecTransformCtxPtr transformCtx) {
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->inNodes == NULL, -1);
    xmlSecAssert2(transform->outNodes == NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    /* execute our transform */
    transform->inNodes = nodes;
    ret = xmlSecTransformExecute(transform, 1, transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformExecute",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    /* push result to the next transform (if exist) */
    if(transform->next != NULL) {
        ret = xmlSecTransformPushXml(transform->next, transform->outNodes, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformPushXml",
                                xmlSecTransformGetName(transform));
            return(-1);
        }
    }
    return(0);
}

/**
 * @brief Pops data, processes via execute method, and returns result nodes.
 * @details Pops data from previous transform in the chain, processes the data
 * by calling transform's execute method and returns result in @p nodes.
 * @param transform the pointer to transform object.
 * @param nodes the pointer to store popinter to result nodes.
 * @param transformCtx the pointer to transform context object.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformDefaultPopXml(xmlSecTransformPtr transform, xmlSecNodeSetPtr* nodes,
                            xmlSecTransformCtxPtr transformCtx) {
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->inNodes == NULL, -1);
    xmlSecAssert2(transform->outNodes == NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    /* pop result from the prev transform (if exist) */
    if(transform->prev != NULL) {
        ret = xmlSecTransformPopXml(transform->prev, &(transform->inNodes), transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformPopXml",
                                xmlSecTransformGetName(transform));
            return(-1);
        }
    }

    /* execute our transform */
    ret = xmlSecTransformExecute(transform, 1, transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformExecute",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    /* return result if requested */
    if(nodes != NULL) {
        (*nodes) = transform->outNodes;
    }

    return(0);
}

/******************************************************************************
 *
 * Transform Ids list
 *
  *****************************************************************************/
static xmlSecPtrListKlass xmlSecTransformIdListKlass = {
    BAD_CAST "transform-ids-list",
    NULL,                                                       /* xmlSecPtrDuplicateItemMethod duplicateItem; */
    NULL,                                                       /* xmlSecPtrDestroyItemMethod destroyItem; */
    NULL,                                                       /* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    NULL,                                                       /* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

/**
 * @brief The transform id list klass.
 *
 * @return pointer to the transform id list klass.
 */
xmlSecPtrListId
xmlSecTransformIdListGetKlass(void) {
    return(&xmlSecTransformIdListKlass);
}

/**
 * @brief Lookups @p dataId in @p list.
 * @param list the pointer to transform ids list.
 * @param transformId the transform klass.
 *
 * @return 1 if @p dataId is found in the @p list, 0 if not and a negative
 * value if an error occurs.
 */
int
xmlSecTransformIdListFind(xmlSecPtrListPtr list, xmlSecTransformId transformId) {
    xmlSecSize i, size;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecTransformIdListId), -1);
    xmlSecAssert2(transformId != NULL, -1);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        if((xmlSecTransformId)xmlSecPtrListGetItem(list, i) == transformId) {
            return(1);
        }
    }
    return(0);
}

/**
 * @brief Looks up a transform klass by href and usage in the list.
 * @details Lookups data klass in the list with given @p href and @p usage in @p list.
 * @param list the pointer to transform ids list.
 * @param href the desired transform klass href.
 * @param usage the desired transform usage.
 *
 * @return transform klass is found and NULL otherwise.
 */
xmlSecTransformId
xmlSecTransformIdListFindByHref(xmlSecPtrListPtr list, const xmlChar* href,
                            xmlSecTransformUsage usage) {
    xmlSecTransformId transformId;
    xmlSecSize i, size;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecTransformIdListId), xmlSecTransformIdUnknown);
    xmlSecAssert2(href != NULL, xmlSecTransformIdUnknown);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        transformId = (xmlSecTransformId)xmlSecPtrListGetItem(list, i);
        xmlSecAssert2(transformId != xmlSecTransformIdUnknown, xmlSecTransformIdUnknown);

        if(((usage & transformId->usage) != 0) && (transformId->href != NULL) &&
           xmlStrEqual(href, transformId->href)) {
           return(transformId);
        }
    }
    return(xmlSecTransformIdUnknown);
}

/**
 * @brief Looks up a transform klass by name and usage in the list.
 * @details Lookups data klass in the list with given @p name and @p usage in @p list.
 * @param list the pointer to transform ids list.
 * @param name the desired transform klass name.
 * @param usage the desired transform usage.
 *
 * @return transform klass is found and NULL otherwise.
 */
xmlSecTransformId
xmlSecTransformIdListFindByName(xmlSecPtrListPtr list, const xmlChar* name,
                            xmlSecTransformUsage usage) {
    xmlSecTransformId transformId;
    xmlSecSize i, size;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecTransformIdListId), xmlSecTransformIdUnknown);
    xmlSecAssert2(name != NULL, xmlSecTransformIdUnknown);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        transformId = (xmlSecTransformId)xmlSecPtrListGetItem(list, i);
        xmlSecAssert2(transformId != xmlSecTransformIdUnknown, xmlSecTransformIdUnknown);

        if(((usage & transformId->usage) != 0) && (transformId->name != NULL) &&
           xmlStrEqual(name, BAD_CAST transformId->name)) {

           return(transformId);
        }
    }
    return(xmlSecTransformIdUnknown);
}

/**
 * @brief Prints transform ids list debug information to @p output.
 * @details Prints binary transform debug information to @p output.
 * @param list the pointer to transform ids list.
 * @param output the pointer to output FILE.
 */
void
xmlSecTransformIdListDebugDump(xmlSecPtrListPtr list, FILE* output) {
    xmlSecTransformId transformId;
    xmlSecSize i, size;

    xmlSecAssert(xmlSecPtrListCheckId(list, xmlSecTransformIdListId));
    xmlSecAssert(output != NULL);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        transformId = (xmlSecTransformId)xmlSecPtrListGetItem(list, i);
        xmlSecAssert(transformId != NULL);
        xmlSecAssert(transformId->name != NULL);

        if(i > 0) {
            fprintf(output, ",\"%s\"", transformId->name);
        } else {
            fprintf(output, "\"%s\"", transformId->name);
        }
    }
    fprintf(output, "\n");
}

/**
 * @brief Prints transform ids list debug information to @p output in XML format.
 * @details Prints binary transform debug information to @p output in XML format.
 * @param list the pointer to transform ids list.
 * @param output the pointer to output FILE.
 */
void
xmlSecTransformIdListDebugXmlDump(xmlSecPtrListPtr list, FILE* output) {
    xmlSecTransformId transformId;
    xmlSecSize i, size;

    xmlSecAssert(xmlSecPtrListCheckId(list, xmlSecTransformIdListId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<TransformIdsList>\n");
    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        transformId = (xmlSecTransformId)xmlSecPtrListGetItem(list, i);
        xmlSecAssert(transformId != NULL);
        xmlSecAssert(transformId->name != NULL);

        fprintf(output, "<TransformId name=\"");
        xmlSecPrintXmlString(output, transformId->name);
        fprintf(output, "\" />");
    }
    fprintf(output, "</TransformIdsList>\n");
}

/******************************************************************************
 *
 * IO buffers for transforms
 *
  *****************************************************************************/
typedef struct _xmlSecTransformIOBuffer                 xmlSecTransformIOBuffer,
                                                        *xmlSecTransformIOBufferPtr;
typedef enum {
    xmlSecTransformIOBufferModeRead,
    xmlSecTransformIOBufferModeWrite
} xmlSecTransformIOBufferMode;

struct _xmlSecTransformIOBuffer {
    xmlSecTransformIOBufferMode         mode;
    xmlSecTransformPtr                  transform;
    xmlSecTransformCtxPtr               transformCtx;
};

static xmlSecTransformIOBufferPtr xmlSecTransformIOBufferCreate (xmlSecTransformIOBufferMode mode,
                                                                 xmlSecTransformPtr transform,
                                                                 xmlSecTransformCtxPtr transformCtx);
static void     xmlSecTransformIOBufferDestroy                  (xmlSecTransformIOBufferPtr buffer);
static int      xmlSecTransformIOBufferRead                     (xmlSecTransformIOBufferPtr buffer,
                                                                 xmlSecByte *buf,
                                                                 int len);
static int      xmlSecTransformIOBufferWrite                    (xmlSecTransformIOBufferPtr buffer,
                                                                 const xmlSecByte *buf,
                                                                 int len);
static int      xmlSecTransformIOBufferClose                    (xmlSecTransformIOBufferPtr buffer);


/**
 * @brief Creates an output buffer to write data to @p transform.
 * @details Creates output buffer to write data to @p transform.
 * @param transform the pointer to transform.
 * @param transformCtx the pointer to transform context object.
 *
 * @return pointer to new output buffer or NULL if an error occurs.
 */
xmlOutputBufferPtr
xmlSecTransformCreateOutputBuffer(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecTransformIOBufferPtr buffer;
    xmlSecTransformDataType type;
    xmlOutputBufferPtr output;

    xmlSecAssert2(xmlSecTransformIsValid(transform), NULL);
    xmlSecAssert2(transformCtx != NULL, NULL);

    /* check that we have binary push method for this transform */
    type = xmlSecTransformDefaultGetDataType(transform, xmlSecTransformModePush, transformCtx);
    if((type & xmlSecTransformDataTypeBin) == 0) {
        xmlSecInvalidTransfromError2(transform,
            "push binary data not supported, type=\"" XMLSEC_ENUM_FMT "\"",
            XMLSEC_ENUM_CAST(type));
        return(NULL);
    }

    buffer = xmlSecTransformIOBufferCreate(xmlSecTransformIOBufferModeWrite, transform, transformCtx);
    if(buffer == NULL) {
        xmlSecInternalError("xmlSecTransformIOBufferCreate",
                            xmlSecTransformGetName(transform));
        return(NULL);
    }

    output = xmlOutputBufferCreateIO((xmlOutputWriteCallback)xmlSecTransformIOBufferWrite,
                                     (xmlOutputCloseCallback)xmlSecTransformIOBufferClose,
                                     buffer,
                                     NULL);
    if(output == NULL) {
        xmlSecXmlError("xmlOutputBufferCreateIO", xmlSecTransformGetName(transform));
        xmlSecTransformIOBufferDestroy(buffer);
        return(NULL);
    }

    return(output);
}

/**
 * @brief Creates an input buffer to read data from @p transform.
 * @details Creates input buffer to read data from @p transform.
 * @param transform the pointer to transform.
 * @param transformCtx the pointer to transform context object.
 *
 * @return pointer to new input buffer or NULL if an error occurs.
 */
xmlParserInputBufferPtr
xmlSecTransformCreateInputBuffer(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecTransformIOBufferPtr buffer;
    xmlSecTransformDataType type;
    xmlParserInputBufferPtr input;

    xmlSecAssert2(xmlSecTransformIsValid(transform), NULL);
    xmlSecAssert2(transformCtx != NULL, NULL);

    /* check that we have binary pop method for this transform */
    type = xmlSecTransformDefaultGetDataType(transform, xmlSecTransformModePop, transformCtx);
    if((type & xmlSecTransformDataTypeBin) == 0) {
        xmlSecInvalidTransfromError2(transform,
            "pop binary data not supported, type=\"" XMLSEC_ENUM_FMT "\"",
            XMLSEC_ENUM_CAST(type));
        return(NULL);
    }

    buffer = xmlSecTransformIOBufferCreate(xmlSecTransformIOBufferModeRead, transform, transformCtx);
    if(buffer == NULL) {
        xmlSecInternalError("xmlSecTransformIOBufferCreate",
                            xmlSecTransformGetName(transform));
        return(NULL);
    }

    input = xmlParserInputBufferCreateIO((xmlInputReadCallback)xmlSecTransformIOBufferRead,
                                     (xmlInputCloseCallback)xmlSecTransformIOBufferClose,
                                     buffer,
                                     XML_CHAR_ENCODING_NONE);
    if(input == NULL) {
        xmlSecXmlError("xmlParserInputBufferCreateIO", xmlSecTransformGetName(transform));
        xmlSecTransformIOBufferDestroy(buffer);
        return(NULL);
    }

    return(input);
}

static xmlSecTransformIOBufferPtr
xmlSecTransformIOBufferCreate(xmlSecTransformIOBufferMode mode, xmlSecTransformPtr transform,
                              xmlSecTransformCtxPtr transformCtx) {
    xmlSecTransformIOBufferPtr buffer;

    xmlSecAssert2(xmlSecTransformIsValid(transform), NULL);
    xmlSecAssert2(transformCtx != NULL, NULL);

    buffer = (xmlSecTransformIOBufferPtr)xmlMalloc(sizeof(xmlSecTransformIOBuffer));
    if(buffer == NULL) {
        xmlSecMallocError(sizeof(xmlSecTransformIOBuffer), NULL);
        return(NULL);
    }
    memset(buffer, 0, sizeof(xmlSecTransformIOBuffer));

    buffer->mode = mode;
    buffer->transform = transform;
    buffer->transformCtx = transformCtx;

    return(buffer);
}

static void
xmlSecTransformIOBufferDestroy(xmlSecTransformIOBufferPtr buffer) {
    xmlSecAssert(buffer != NULL);

    memset(buffer, 0, sizeof(xmlSecTransformIOBuffer));
    xmlFree(buffer);
}

static int
xmlSecTransformIOBufferRead(xmlSecTransformIOBufferPtr buffer,
                            xmlSecByte *buf, int len) {
    xmlSecSize size;
    int ret;
    int res;

    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(buffer->mode == xmlSecTransformIOBufferModeRead, -1);
    xmlSecAssert2(xmlSecTransformIsValid(buffer->transform), -1);
    xmlSecAssert2(buffer->transformCtx != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return(-1), xmlSecTransformGetName(buffer->transform));
    ret = xmlSecTransformPopBin(buffer->transform, buf, size, &size, buffer->transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPopBin",
                            xmlSecTransformGetName(buffer->transform));
        return(-1);
    }
    XMLSEC_SAFE_CAST_SIZE_TO_INT(size, res, return(-1), NULL);
    return(res);
}

static int
xmlSecTransformIOBufferWrite(xmlSecTransformIOBufferPtr buffer,
                            const xmlSecByte *buf, int len) {
    xmlSecSize size;
    int ret;
    int res;

    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(buffer->mode == xmlSecTransformIOBufferModeWrite, -1);
    xmlSecAssert2(xmlSecTransformIsValid(buffer->transform), -1);
    xmlSecAssert2(buffer->transformCtx != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return(-1), xmlSecTransformGetName(buffer->transform));
    ret = xmlSecTransformPushBin(buffer->transform, buf, size, 0, buffer->transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPushBin",
                            xmlSecTransformGetName(buffer->transform));
        return(-1);
    }
    XMLSEC_SAFE_CAST_SIZE_TO_INT(size, res, return(-1), NULL);
    return(res);
}

static int
xmlSecTransformIOBufferClose(xmlSecTransformIOBufferPtr buffer) {
    int ret;

    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(xmlSecTransformIsValid(buffer->transform), -1);
    xmlSecAssert2(buffer->transformCtx != NULL, -1);

    /* need to flush write buffer before destroying */
    if(buffer->mode == xmlSecTransformIOBufferModeWrite) {
        ret = xmlSecTransformPushBin(buffer->transform, NULL, 0, 1, buffer->transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformPushBin",
                                xmlSecTransformGetName(buffer->transform));
            return(-1);
        }
    }

    xmlSecTransformIOBufferDestroy(buffer);
    return(0);
}
