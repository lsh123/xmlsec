/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:xmlenc
 * @Short_description: XML Encryption support.
 * @Stability: Stable
 *
 * [XML Encryption](http://www.w3.org/TR/xmlenc-core) implementation.
 */

#include "globals.h"

#ifndef XMLSEC_NO_XMLENC

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/parser.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/errors.h>

#include "cast_helpers.h"

static int      xmlSecEncCtxEncDataNodeRead             (xmlSecEncCtxPtr encCtx,
                                                         xmlNodePtr node);
static int      xmlSecEncCtxEncDataNodeWrite            (xmlSecEncCtxPtr encCtx);
static int      xmlSecEncCtxCipherDataNodeRead          (xmlSecEncCtxPtr encCtx,
                                                         xmlNodePtr node);
static int      xmlSecEncCtxCipherReferenceNodeRead     (xmlSecEncCtxPtr encCtx,
                                                         xmlNodePtr node);

/* The ID attribute in XMLEnc is 'Id' */
static const xmlChar*           xmlSecEncIds[] = { BAD_CAST "Id", NULL };


/**
 * xmlSecEncCtxCreate:
 * @keysMngr:           the pointer to keys manager.
 *
 * Creates <enc:EncryptedData/> element processing context.
 * The caller is responsible for destroying returned object by calling
 * #xmlSecEncCtxDestroy function.
 *
 * Returns: pointer to newly allocated context object or NULL if an error
 * occurs.
 */
xmlSecEncCtxPtr
xmlSecEncCtxCreate(xmlSecKeysMngrPtr keysMngr) {
    xmlSecEncCtxPtr encCtx;
    int ret;

    encCtx = (xmlSecEncCtxPtr) xmlMalloc(sizeof(xmlSecEncCtx));
    if(encCtx == NULL) {
        xmlSecMallocError(sizeof(xmlSecEncCtx), NULL);
        return(NULL);
    }

    ret = xmlSecEncCtxInitialize(encCtx, keysMngr);
    if(ret < 0) {
        xmlSecInternalError("xmlSecEncCtxInitialize", NULL);
        xmlSecEncCtxDestroy(encCtx);
        return(NULL);
    }
    return(encCtx);
}

/**
 * xmlSecEncCtxDestroy:
 * @encCtx:             the pointer to <enc:EncryptedData/> processing context.
 *
 * Destroy context object created with #xmlSecEncCtxCreate function.
 */
void
xmlSecEncCtxDestroy(xmlSecEncCtxPtr encCtx) {
    xmlSecAssert(encCtx != NULL);

    xmlSecEncCtxFinalize(encCtx);
    xmlFree(encCtx);
}

static void
xmlSecEncCtxSetDefaults(xmlSecEncCtxPtr encCtx) {
    xmlSecAssert(encCtx != NULL);

    encCtx->keyInfoReadCtx.mode = xmlSecKeyInfoModeRead;

    /* it's not wise to write private key :) */
    encCtx->keyInfoWriteCtx.mode = xmlSecKeyInfoModeWrite;
    encCtx->keyInfoWriteCtx.keyReq.keyType = xmlSecKeyDataTypePublic;
}

/**
 * xmlSecEncCtxInitialize:
 * @encCtx:             the pointer to <enc:EncryptedData/> processing context.
 * @keysMngr:           the pointer to keys manager.
 *
 * Initializes <enc:EncryptedData/> element processing context.
 * The caller is responsible for cleaning up returned object by calling
 * #xmlSecEncCtxFinalize function.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecEncCtxInitialize(xmlSecEncCtxPtr encCtx, xmlSecKeysMngrPtr keysMngr) {
    int ret;

    xmlSecAssert2(encCtx != NULL, -1);

    memset(encCtx, 0, sizeof(xmlSecEncCtx));

    /* initialize key info */
    ret = xmlSecKeyInfoCtxInitialize(&(encCtx->keyInfoReadCtx), keysMngr);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyInfoCtxInitialize", NULL);
        return(-1);
    }

    ret = xmlSecKeyInfoCtxInitialize(&(encCtx->keyInfoWriteCtx), keysMngr);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyInfoCtxInitialize", NULL);
        return(-1);
    }

    /* initializes transforms encCtx */
    ret = xmlSecTransformCtxInitialize(&(encCtx->transformCtx));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformCtxInitialize", NULL);
        return(-1);
    }

    xmlSecEncCtxSetDefaults(encCtx);
    return(0);
}

/**
 * xmlSecEncCtxFinalize:
 * @encCtx:             the pointer to <enc:EncryptedData/> processing context.
 *
 * Cleans up @encCtx object.
 */
void
xmlSecEncCtxFinalize(xmlSecEncCtxPtr encCtx) {
    xmlSecAssert(encCtx != NULL);

    xmlSecEncCtxReset(encCtx);

    xmlSecTransformCtxFinalize(&(encCtx->transformCtx));
    xmlSecKeyInfoCtxFinalize(&(encCtx->keyInfoReadCtx));
    xmlSecKeyInfoCtxFinalize(&(encCtx->keyInfoWriteCtx));

    memset(encCtx, 0, sizeof(xmlSecEncCtx));
}

/**
 * xmlSecEncCtxReset:
 * @encCtx:             the pointer to <enc:EncryptedData/> processing context.
 *
 * Resets @encCtx object, user settings are not touched.
 */
void
xmlSecEncCtxReset(xmlSecEncCtxPtr encCtx) {
    xmlSecAssert(encCtx != NULL);

    xmlSecTransformCtxReset(&(encCtx->transformCtx));
    xmlSecKeyInfoCtxReset(&(encCtx->keyInfoReadCtx));
    xmlSecKeyInfoCtxReset(&(encCtx->keyInfoWriteCtx));

    encCtx->operation           = xmlSecTransformOperationNone;
    encCtx->result              = NULL;
    encCtx->resultBase64Encoded = 0;
    encCtx->resultReplaced      = 0;
    encCtx->encMethod           = NULL;

    if (encCtx->replacedNodeList != NULL) {
                xmlFreeNodeList(encCtx->replacedNodeList);
        encCtx->replacedNodeList = NULL;
    }

    if(encCtx->encKey != NULL) {
        xmlSecKeyDestroy(encCtx->encKey);
        encCtx->encKey = NULL;
    }

    if(encCtx->id != NULL) {
        xmlFree(encCtx->id);
        encCtx->id = NULL;
    }

    if(encCtx->type != NULL) {
        xmlFree(encCtx->type);
        encCtx->type = NULL;
    }

    if(encCtx->mimeType != NULL) {
        xmlFree(encCtx->mimeType);
        encCtx->mimeType = NULL;
    }

    if(encCtx->encoding != NULL) {
        xmlFree(encCtx->encoding);
        encCtx->encoding = NULL;
    }

    if(encCtx->recipient != NULL) {
        xmlFree(encCtx->recipient);
        encCtx->recipient = NULL;
    }

    if(encCtx->carriedKeyName != NULL) {
        xmlFree(encCtx->carriedKeyName);
        encCtx->carriedKeyName = NULL;
    }

    encCtx->encDataNode = encCtx->encMethodNode =
    encCtx->keyInfoNode = encCtx->cipherValueNode = NULL;

    xmlSecEncCtxSetDefaults(encCtx);
}

/**
 * xmlSecEncCtxCopyUserPref:
 * @dst:                the pointer to destination context.
 * @src:                the pointer to source context.
 *
 * Copies user preference from @src context to @dst.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecEncCtxCopyUserPref(xmlSecEncCtxPtr dst, xmlSecEncCtxPtr src) {
    int ret;

    xmlSecAssert2(dst != NULL, -1);
    xmlSecAssert2(src != NULL, -1);

    dst->userData       = src->userData;
    dst->flags          = src->flags;
    dst->flags2         = src->flags2;
    dst->defEncMethodId = src->defEncMethodId;
    dst->mode           = src->mode;

    ret = xmlSecTransformCtxCopyUserPref(&(dst->transformCtx), &(src->transformCtx));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformCtxCopyUserPref", NULL);
        return(-1);
    }

    ret = xmlSecKeyInfoCtxCopyUserPref(&(dst->keyInfoReadCtx), &(src->keyInfoReadCtx));
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyInfoCtxCopyUserPref", NULL);
        return(-1);
    }

    ret = xmlSecKeyInfoCtxCopyUserPref(&(dst->keyInfoWriteCtx), &(src->keyInfoWriteCtx));
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyInfoCtxCopyUserPref", NULL);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecEncCtxBinaryEncrypt:
 * @encCtx:             the pointer to <enc:EncryptedData/> processing context.
 * @tmpl:               the pointer to <enc:EncryptedData/> template node.
 * @data:               the pointer for binary buffer.
 * @dataSize:           the @data buffer size.
 *
 * Encrypts @data according to template @tmpl.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecEncCtxBinaryEncrypt(xmlSecEncCtxPtr encCtx, xmlNodePtr tmpl,
                          const xmlSecByte* data, xmlSecSize dataSize) {
    int ret;

    xmlSecAssert2(encCtx != NULL, -1);
    xmlSecAssert2(encCtx->result == NULL, -1);
    xmlSecAssert2(tmpl != NULL, -1);
    xmlSecAssert2(data != NULL, -1);

    /* initialize context and add ID atributes to the list of known ids */
    encCtx->operation = xmlSecTransformOperationEncrypt;
    xmlSecAddIDs(tmpl->doc, tmpl, xmlSecEncIds);

    /* read the template and set encryption method, key, etc. */
    ret = xmlSecEncCtxEncDataNodeRead(encCtx, tmpl);
    if(ret < 0) {
        xmlSecInternalError("xmlSecEncCtxEncDataNodeRead", NULL);
        return(-1);
    }

    ret = xmlSecTransformCtxBinaryExecute(&(encCtx->transformCtx), data, dataSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecTransformCtxBinaryExecute", NULL,
                             "dataSize=" XMLSEC_SIZE_FMT,  dataSize);
        return(-1);
    }

    encCtx->result = encCtx->transformCtx.result;
    xmlSecAssert2(encCtx->result != NULL, -1);

    ret = xmlSecEncCtxEncDataNodeWrite(encCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecEncCtxEncDataNodeWrite", NULL);
        return(-1);
    }
    return(0);
}

/**
 * xmlSecEncCtxXmlEncrypt:
 * @encCtx:             the pointer to <enc:EncryptedData/> processing context.
 * @tmpl:               the pointer to <enc:EncryptedData/> template node.
 * @node:               the pointer to node for encryption.
 *
 * Encrypts @node according to template @tmpl. If requested, @node is replaced
 * with result <enc:EncryptedData/> node.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecEncCtxXmlEncrypt(xmlSecEncCtxPtr encCtx, xmlNodePtr tmpl, xmlNodePtr node) {
    xmlOutputBufferPtr output;
    int ret;

    xmlSecAssert2(encCtx != NULL, -1);
    xmlSecAssert2(encCtx->result == NULL, -1);
    xmlSecAssert2(tmpl != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(node->doc != NULL, -1);

    /* initialize context and add ID atributes to the list of known ids */
    encCtx->operation = xmlSecTransformOperationEncrypt;
    xmlSecAddIDs(tmpl->doc, tmpl, xmlSecEncIds);

    /* read the template and set encryption method, key, etc. */
    ret = xmlSecEncCtxEncDataNodeRead(encCtx, tmpl);
    if(ret < 0) {
        xmlSecInternalError("xmlSecEncCtxEncDataNodeRead", NULL);
        return(-1);
    }

    ret = xmlSecTransformCtxPrepare(&(encCtx->transformCtx), xmlSecTransformDataTypeBin);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformCtxPrepare(TypeBin)", NULL);
        return(-1);
    }

    xmlSecAssert2(encCtx->transformCtx.first != NULL, -1);
    output = xmlSecTransformCreateOutputBuffer(encCtx->transformCtx.first,
                                                &(encCtx->transformCtx));
    if(output == NULL) {
        xmlSecInternalError("xmlSecTransformCreateOutputBuffer",
                            xmlSecTransformGetName(encCtx->transformCtx.first));
        return(-1);
    }

    /* push data thru */
    if((encCtx->type != NULL) && xmlStrEqual(encCtx->type, xmlSecTypeEncElement)) {
        /* get the content of the node */
        xmlNodeDumpOutput(output, node->doc, node, 0, 0, NULL);
    } else if((encCtx->type != NULL) && xmlStrEqual(encCtx->type, xmlSecTypeEncContent)) {
        xmlNodePtr cur;

        /* get the content of the nodes childs */
        for(cur = node->children; cur != NULL; cur = cur->next) {
            xmlNodeDumpOutput(output, node->doc, cur, 0, 0, NULL);
        }
    } else {
        xmlSecInvalidStringTypeError("encryption type", encCtx->type,
                "supported encryption type", NULL);
        (void)xmlOutputBufferClose(output);
        return(-1);
    }

    /* close the buffer and flush everything */
    ret = xmlOutputBufferClose(output);
    if(ret < 0) {
        xmlSecXmlError("xmlOutputBufferClose", NULL);
        return(-1);
    }

    encCtx->result = encCtx->transformCtx.result;
    xmlSecAssert2(encCtx->result != NULL, -1);

    ret = xmlSecEncCtxEncDataNodeWrite(encCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecEncCtxEncDataNodeWrite", NULL);
        return(-1);
    }

    /* now we need to update our original document */
    if((encCtx->type != NULL) && xmlStrEqual(encCtx->type, xmlSecTypeEncElement)) {
        /* check if we need to return the replaced node */
        if((encCtx->flags & XMLSEC_ENC_RETURN_REPLACED_NODE) != 0) {
            ret = xmlSecReplaceNodeAndReturn(node, tmpl, &(encCtx->replacedNodeList));
            if(ret < 0) {
                xmlSecInternalError("xmlSecReplaceNodeAndReturn",
                                    xmlSecNodeGetName(node));
                return(-1);
            }
        } else {
            ret = xmlSecReplaceNode(node, tmpl);
            if(ret < 0) {
                xmlSecInternalError("xmlSecReplaceNode",
                                    xmlSecNodeGetName(node));
                return(-1);
            }
        }
        encCtx->resultReplaced = 1;
    } else if((encCtx->type != NULL) && xmlStrEqual(encCtx->type, xmlSecTypeEncContent)) {
        /* check if we need to return the replaced node */
        if((encCtx->flags & XMLSEC_ENC_RETURN_REPLACED_NODE) != 0) {
            ret = xmlSecReplaceContentAndReturn(node, tmpl, &(encCtx->replacedNodeList));
            if(ret < 0) {
                xmlSecInternalError("xmlSecReplaceContentAndReturn",
                                    xmlSecNodeGetName(node));
                return(-1);
            }
        } else {
            ret = xmlSecReplaceContent(node, tmpl);
            if(ret < 0) {
                xmlSecInternalError("xmlSecReplaceContent",
                                    xmlSecNodeGetName(node));
                return(-1);
            }
        }
        encCtx->resultReplaced = 1;
    } else {
        /* we should've caught this error before */
        xmlSecInvalidStringTypeError("encryption type", encCtx->type,
                "supported encryption type", NULL);
        return(-1);
    }
    /* done */
    return(0);
}

/**
 * xmlSecEncCtxUriEncrypt:
 * @encCtx:             the pointer to <enc:EncryptedData/> processing context.
 * @tmpl:               the pointer to <enc:EncryptedData/> template node.
 * @uri:                the URI.
 *
 * Encrypts data from @uri according to template @tmpl.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecEncCtxUriEncrypt(xmlSecEncCtxPtr encCtx, xmlNodePtr tmpl, const xmlChar *uri) {
    int ret;

    xmlSecAssert2(encCtx != NULL, -1);
    xmlSecAssert2(encCtx->result == NULL, -1);
    xmlSecAssert2(tmpl != NULL, -1);
    xmlSecAssert2(uri != NULL, -1);

    /* initialize context and add ID atributes to the list of known ids */
    encCtx->operation = xmlSecTransformOperationEncrypt;
    xmlSecAddIDs(tmpl->doc, tmpl, xmlSecEncIds);

    /* we need to add input uri transform first */
    ret = xmlSecTransformCtxSetUri(&(encCtx->transformCtx), uri, tmpl);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecTransformCtxSetUri", NULL,
                             "uri=%s", xmlSecErrorsSafeString(uri));
        return(-1);
    }

    /* read the template and set encryption method, key, etc. */
    ret = xmlSecEncCtxEncDataNodeRead(encCtx, tmpl);
    if(ret < 0) {
        xmlSecInternalError("xmlSecEncCtxEncDataNodeRead", NULL);
        return(-1);
    }

    /* encrypt the data */
    ret = xmlSecTransformCtxExecute(&(encCtx->transformCtx), tmpl->doc);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformCtxExecute", NULL);
        return(-1);
    }

    encCtx->result = encCtx->transformCtx.result;
    xmlSecAssert2(encCtx->result != NULL, -1);

    ret = xmlSecEncCtxEncDataNodeWrite(encCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecEncCtxEncDataNodeWrite", NULL);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecEncCtxDecrypt:
 * @encCtx:             the pointer to <enc:EncryptedData/> processing context.
 * @node:               the pointer to <enc:EncryptedData/> node.
 *
 * Decrypts @node and if necessary replaces @node with decrypted data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecEncCtxDecrypt(xmlSecEncCtxPtr encCtx, xmlNodePtr node) {
    xmlSecBufferPtr buffer;
    int ret;

    xmlSecAssert2(encCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* decrypt */
    buffer = xmlSecEncCtxDecryptToBuffer(encCtx, node);
    if(buffer == NULL) {
        xmlSecInternalError("xmlSecEncCtxDecryptToBuffer", NULL);
        return(-1);
    }

    /* replace original node if requested */
    if((encCtx->type != NULL) && xmlStrEqual(encCtx->type, xmlSecTypeEncElement)) {
        /* check if we need to return the replaced node */
        if((encCtx->flags & XMLSEC_ENC_RETURN_REPLACED_NODE) != 0) {
                ret = xmlSecReplaceNodeBufferAndReturn(node, xmlSecBufferGetData(buffer),  xmlSecBufferGetSize(buffer), &(encCtx->replacedNodeList));
                if(ret < 0) {
                    xmlSecInternalError("xmlSecReplaceNodeBufferAndReturn",
                                        xmlSecNodeGetName(node));
                    return(-1);
                }
        } else {
                ret = xmlSecReplaceNodeBuffer(node, xmlSecBufferGetData(buffer),  xmlSecBufferGetSize(buffer));
                if(ret < 0) {
                    xmlSecInternalError("xmlSecReplaceNodeBuffer",
                                        xmlSecNodeGetName(node));
                    return(-1);
                }
        }

        encCtx->resultReplaced = 1;
    } else if((encCtx->type != NULL) && xmlStrEqual(encCtx->type, xmlSecTypeEncContent)) {
        /* replace the node with the buffer */

        /* check if we need to return the replaced node */
        if((encCtx->flags & XMLSEC_ENC_RETURN_REPLACED_NODE) != 0) {
                ret = xmlSecReplaceNodeBufferAndReturn(node, xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer), &(encCtx->replacedNodeList));
                if(ret < 0) {
                    xmlSecInternalError("xmlSecReplaceNodeBufferAndReturn",
                                        xmlSecNodeGetName(node));
                    return(-1);
                }
        } else {
            ret = xmlSecReplaceNodeBuffer(node, xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer));
                if(ret < 0) {
                    xmlSecInternalError("xmlSecReplaceNodeBuffer",
                                        xmlSecNodeGetName(node));
                    return(-1);
                }
        }
        encCtx->resultReplaced = 1;
    }

    return(0);
}

/**
 * xmlSecEncCtxDecryptToBuffer:
 * @encCtx:             the pointer to encryption processing context.
 * @node:               the pointer to <enc:EncryptedData/> node.
 *
 * Decrypts @node data to the result.
 *
 * Returns: a buffer with key on success or NULL if an error occurs.
 */
xmlSecBufferPtr
xmlSecEncCtxDecryptToBuffer(xmlSecEncCtxPtr encCtx, xmlNodePtr node) {
    xmlSecBufferPtr res = NULL;
    xmlChar* data = NULL;
    int ret;

    xmlSecAssert2(encCtx != NULL, NULL);
    xmlSecAssert2(encCtx->result == NULL, NULL);
    xmlSecAssert2(node != NULL, NULL);

    /* initialize context and add ID atributes to the list of known ids */
    encCtx->operation = xmlSecTransformOperationDecrypt;
    xmlSecAddIDs(node->doc, node, xmlSecEncIds);

    ret = xmlSecEncCtxEncDataNodeRead(encCtx, node);
    if(ret < 0) {
        xmlSecInternalError("xmlSecEncCtxEncDataNodeRead", NULL);
        goto done;
    }

    /* decrypt the data */
    if(encCtx->cipherValueNode != NULL) {
        data = xmlNodeGetContent(encCtx->cipherValueNode);
        if(data == NULL) {
            xmlSecInvalidNodeContentError(encCtx->cipherValueNode, NULL, "empty");
            goto done;
        }

        ret = xmlSecTransformCtxBinaryExecute(&(encCtx->transformCtx), data, xmlSecStrlen(data));
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformCtxBinaryExecute", NULL);
            goto done;
        }
    } else {
        ret = xmlSecTransformCtxExecute(&(encCtx->transformCtx), node->doc);
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformCtxExecute", NULL);
            goto done;
        }
    }

    /* success  */
    res = encCtx->result = encCtx->transformCtx.result;
    xmlSecAssert2(encCtx->result != NULL, NULL);

done:
    if(data != NULL) {
        xmlFree(data);
    }
    return(res);
}

static int
xmlSecEncCtxEncDataNodeRead(xmlSecEncCtxPtr encCtx, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(encCtx != NULL, -1);
    xmlSecAssert2((encCtx->operation == xmlSecTransformOperationEncrypt) || (encCtx->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(node != NULL, -1);

    switch(encCtx->mode) {
        case xmlEncCtxModeEncryptedData:
            if(!xmlSecCheckNodeName(node, xmlSecNodeEncryptedData, xmlSecEncNs)) {
                xmlSecInvalidNodeError(node, xmlSecNodeEncryptedData, NULL);
                return(-1);
            }
            break;
        case xmlEncCtxModeEncryptedKey:
            if(!xmlSecCheckNodeName(node, xmlSecNodeEncryptedKey, xmlSecEncNs)) {
                xmlSecInvalidNodeError(node, xmlSecNodeEncryptedKey, NULL);
                return(-1);
            }
            break;
    }

    /* first read node data */
    xmlSecAssert2(encCtx->id == NULL, -1);
    xmlSecAssert2(encCtx->type == NULL, -1);
    xmlSecAssert2(encCtx->mimeType == NULL, -1);
    xmlSecAssert2(encCtx->encoding == NULL, -1);
    xmlSecAssert2(encCtx->recipient == NULL, -1);
    xmlSecAssert2(encCtx->carriedKeyName == NULL, -1);

    encCtx->id = xmlGetProp(node, xmlSecAttrId);
    encCtx->type = xmlGetProp(node, xmlSecAttrType);
    encCtx->mimeType = xmlGetProp(node, xmlSecAttrMimeType);
    encCtx->encoding = xmlGetProp(node, xmlSecAttrEncoding);
    if(encCtx->mode == xmlEncCtxModeEncryptedKey) {
        encCtx->recipient = xmlGetProp(node, xmlSecAttrRecipient);
        /* todo: check recipient? */
    }
    cur = xmlSecGetNextElementNode(node->children);

    /* first node is optional EncryptionMethod, we'll read it later */
    xmlSecAssert2(encCtx->encMethodNode == NULL, -1);
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeEncryptionMethod, xmlSecEncNs))) {
        encCtx->encMethodNode = cur;
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next node is optional KeyInfo, we'll process it later */
    xmlSecAssert2(encCtx->keyInfoNode == NULL, -1);
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeKeyInfo, xmlSecDSigNs))) {
        encCtx->keyInfoNode = cur;
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next is required CipherData node */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeCipherData, xmlSecEncNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeCipherData, NULL);
        return(-1);
    }

    ret = xmlSecEncCtxCipherDataNodeRead(encCtx, cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecEncCtxCipherDataNodeRead", NULL);
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is optional EncryptionProperties node (we simply ignore it) */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeEncryptionProperties, xmlSecEncNs))) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* there are more possible nodes for the <EncryptedKey> node */
    if(encCtx->mode == xmlEncCtxModeEncryptedKey) {
        /* next is optional ReferenceList node (we simply ignore it) */
        if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeReferenceList, xmlSecEncNs))) {
            cur = xmlSecGetNextElementNode(cur->next);
        }

        /* next is optional CarriedKeyName node (we simply ignore it) */
        if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeCarriedKeyName, xmlSecEncNs))) {
            encCtx->carriedKeyName = xmlNodeGetContent(cur);
            if(encCtx->carriedKeyName == NULL) {
                xmlSecInvalidNodeContentError(cur, NULL, "empty");
                return(-1);
            }
            /* TODO: decode the name? */
            cur = xmlSecGetNextElementNode(cur->next);
        }
    }

    /* if there is something left than it's an error */
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        return(-1);
    }

    /* now read the encryption method node */
    xmlSecAssert2(encCtx->encMethod == NULL, -1);
    if(encCtx->encMethodNode != NULL) {
        encCtx->encMethod = xmlSecTransformCtxNodeRead(&(encCtx->transformCtx), encCtx->encMethodNode,
                                                xmlSecTransformUsageEncryptionMethod);
        if(encCtx->encMethod == NULL) {
            xmlSecInternalError("xmlSecTransformCtxNodeRead",
                                xmlSecNodeGetName(encCtx->encMethodNode));
            return(-1);
        }
    } else if(encCtx->defEncMethodId != xmlSecTransformIdUnknown) {
        encCtx->encMethod = xmlSecTransformCtxCreateAndAppend(&(encCtx->transformCtx),
                                                              encCtx->defEncMethodId);
        if(encCtx->encMethod == NULL) {
            xmlSecInternalError("xmlSecTransformCtxCreateAndAppend",
                    xmlSecTransformKlassGetName(encCtx->defEncMethodId));
            return(-1);
        }
    } else {
        xmlSecInvalidDataError("encryption method not specified", NULL);
        return(-1);
    }
    encCtx->encMethod->operation = encCtx->operation;
    encCtx->keyInfoReadCtx.operation = encCtx->operation;
    encCtx->keyInfoWriteCtx.operation = encCtx->operation;

    /* we have encryption method, find key */
    ret = xmlSecTransformSetKeyReq(encCtx->encMethod, &(encCtx->keyInfoReadCtx.keyReq));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformSetKeyReq",
                xmlSecTransformGetName(encCtx->encMethod));
        return(-1);
    }

    /* TODO: KeyInfo node != NULL and encKey != NULL */
    if((encCtx->encKey == NULL) && (encCtx->keyInfoReadCtx.keysMngr != NULL)
                        && (encCtx->keyInfoReadCtx.keysMngr->getKey != NULL)) {
        encCtx->encKey = (encCtx->keyInfoReadCtx.keysMngr->getKey)(encCtx->keyInfoNode,
                                                             &(encCtx->keyInfoReadCtx));
    }

    /* check that we have exactly what we want */
    if((encCtx->encKey == NULL) ||
       (!xmlSecKeyMatch(encCtx->encKey, NULL, &(encCtx->keyInfoReadCtx.keyReq)))) {

        xmlSecOtherError2(XMLSEC_ERRORS_R_KEY_NOT_FOUND, NULL,
                          "encMethod=%s",
                          xmlSecErrorsSafeString(xmlSecTransformGetName(encCtx->encMethod)));
        return(-1);
    }

    /* set the key to the transform */
    ret = xmlSecTransformSetKey(encCtx->encMethod, encCtx->encKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformSetKey",
                            xmlSecTransformGetName(encCtx->encMethod));
        return(-1);
    }

    /* if we need to write result to xml node then we need base64 encode it */
    if((encCtx->operation == xmlSecTransformOperationEncrypt) && (encCtx->cipherValueNode != NULL)) {
        xmlSecTransformPtr base64Encode;

        /* we need to add base64 encode transform */
        base64Encode = xmlSecTransformCtxCreateAndAppend(&(encCtx->transformCtx), xmlSecTransformBase64Id);
        if(base64Encode == NULL) {
            xmlSecInternalError("xmlSecTransformCtxCreateAndAppend", NULL);
            return(-1);
        }
        base64Encode->operation         = xmlSecTransformOperationEncode;
        encCtx->resultBase64Encoded     = 1;
    }

    return(0);
}

static int
xmlSecEncCtxEncDataNodeWrite(xmlSecEncCtxPtr encCtx) {
    int ret;

    xmlSecAssert2(encCtx != NULL, -1);
    xmlSecAssert2(encCtx->result != NULL, -1);
    xmlSecAssert2(encCtx->encKey != NULL, -1);

    /* write encrypted data to xml (if requested) */
    if(encCtx->cipherValueNode != NULL) {
        xmlSecByte* inBuf;
        xmlSecSize inSize;
        int inLen;

        inBuf = xmlSecBufferGetData(encCtx->result);
        inSize = xmlSecBufferGetSize(encCtx->result);
        xmlSecAssert2(inBuf != NULL, -1);
        XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, return(-1), NULL);

        xmlNodeSetContentLen(encCtx->cipherValueNode, inBuf, inLen);
        encCtx->resultReplaced = 1;
    }

    /* update <enc:KeyInfo/> node */
    if(encCtx->keyInfoNode != NULL) {
        ret = xmlSecKeyInfoNodeWrite(encCtx->keyInfoNode, encCtx->encKey, &(encCtx->keyInfoWriteCtx));
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeyInfoNodeWrite", NULL);
            return(-1);
        }
    }

    return(0);
}

static int
xmlSecEncCtxCipherDataNodeRead(xmlSecEncCtxPtr encCtx, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(encCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = xmlSecGetNextElementNode(node->children);

    /* we either have CipherValue or CipherReference node  */
    xmlSecAssert2(encCtx->cipherValueNode == NULL, -1);
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeCipherValue, xmlSecEncNs))) {
        /* don't need data from CipherData node when we are encrypting */
        if(encCtx->operation == xmlSecTransformOperationDecrypt) {
            xmlSecTransformPtr base64Decode;

            /* we need to add base64 decode transform */
            base64Decode = xmlSecTransformCtxCreateAndPrepend(&(encCtx->transformCtx), xmlSecTransformBase64Id);
            if(base64Decode == NULL) {
                xmlSecInternalError("xmlSecTransformCtxCreateAndPrepend", NULL);
                return(-1);
            }
        }
        encCtx->cipherValueNode = cur;
        cur = xmlSecGetNextElementNode(cur->next);
    } else if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeCipherReference, xmlSecEncNs))) {
        /* don't need data from CipherReference node when we are encrypting */
        if(encCtx->operation == xmlSecTransformOperationDecrypt) {
            ret = xmlSecEncCtxCipherReferenceNodeRead(encCtx, cur);
            if(ret < 0) {
                xmlSecInternalError("xmlSecEncCtxCipherReferenceNodeRead",
                                    xmlSecNodeGetName(cur));
                return(-1);
            }
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        return(-1);
    }
    return(0);
}

static int
xmlSecEncCtxCipherReferenceNodeRead(xmlSecEncCtxPtr encCtx, xmlNodePtr node) {
    xmlNodePtr cur;
    xmlChar* uri;
    int ret;

    xmlSecAssert2(encCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first read the optional uri attr and check that we can process it */
    uri = xmlGetProp(node, xmlSecAttrURI);
    ret = xmlSecTransformCtxSetUri(&(encCtx->transformCtx), uri, node);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecTransformCtxSetUri", NULL,
                             "uri=%s", xmlSecErrorsSafeString(uri));
        xmlFree(uri);
        return(-1);
    }
    xmlFree(uri);

    cur = xmlSecGetNextElementNode(node->children);

    /* the only one node is optional Transforms node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeTransforms, xmlSecEncNs))) {
        ret = xmlSecTransformCtxNodesListRead(&(encCtx->transformCtx), cur,
                                    xmlSecTransformUsageDSigTransform);
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformCtxNodesListRead",
                                xmlSecNodeGetName(encCtx->encMethodNode));
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* if there is something left than it's an error */
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        return(-1);
    }
    return(0);
}

/**
 * xmlSecEncCtxDebugDump:
 * @encCtx:             the pointer to <enc:EncryptedData/> processing context.
 * @output:             the pointer to output FILE.
 *
 * Prints the debug information about @encCtx to @output.
 */
void
xmlSecEncCtxDebugDump(xmlSecEncCtxPtr encCtx, FILE* output) {
    xmlSecAssert(encCtx != NULL);
    xmlSecAssert(output != NULL);

    switch(encCtx->mode) {
        case xmlEncCtxModeEncryptedData:
            if(encCtx->operation == xmlSecTransformOperationEncrypt) {
                fprintf(output, "= DATA ENCRYPTION CONTEXT\n");
            } else {
                fprintf(output, "= DATA DECRYPTION CONTEXT\n");
            }
            break;
        case xmlEncCtxModeEncryptedKey:
            if(encCtx->operation == xmlSecTransformOperationEncrypt) {
                fprintf(output, "= KEY ENCRYPTION CONTEXT\n");
            } else {
                fprintf(output, "= KEY DECRYPTION CONTEXT\n");
            }
            break;
    }
    fprintf(output, "== Status: %s\n",
            (encCtx->resultReplaced) ? "replaced" : "not-replaced" );

    fprintf(output, "== flags: 0x%08x\n", encCtx->flags);
    fprintf(output, "== flags2: 0x%08x\n", encCtx->flags2);

    if(encCtx->id != NULL) {
        fprintf(output, "== Id: \"%s\"\n", encCtx->id);
    }
    if(encCtx->type != NULL) {
        fprintf(output, "== Type: \"%s\"\n", encCtx->type);
    }
    if(encCtx->mimeType != NULL) {
        fprintf(output, "== MimeType: \"%s\"\n", encCtx->mimeType);
    }
    if(encCtx->encoding != NULL) {
        fprintf(output, "== Encoding: \"%s\"\n", encCtx->encoding);
    }
    if(encCtx->recipient != NULL) {
        fprintf(output, "== Recipient: \"%s\"\n", encCtx->recipient);
    }
    if(encCtx->carriedKeyName != NULL) {
        fprintf(output, "== CarriedKeyName: \"%s\"\n", encCtx->carriedKeyName);
    }

    fprintf(output, "== Key Info Read Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(encCtx->keyInfoReadCtx), output);

    fprintf(output, "== Key Info Write Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(encCtx->keyInfoWriteCtx), output);

    fprintf(output, "== Encryption Transform Ctx:\n");
    xmlSecTransformCtxDebugDump(&(encCtx->transformCtx), output);

    if(encCtx->encMethod != NULL) {
        fprintf(output, "== Encryption Method:\n");
        xmlSecTransformDebugDump(encCtx->encMethod, output);
    }

    if(encCtx->encKey != NULL) {
        fprintf(output, "== Encryption Key:\n");
        xmlSecKeyDebugDump(encCtx->encKey, output);
    }

    if((encCtx->result != NULL) &&
       (xmlSecBufferGetData(encCtx->result) != NULL) &&
       (encCtx->resultBase64Encoded != 0)) {

        fprintf(output, "== Result - start buffer:\n");
        (void)fwrite(xmlSecBufferGetData(encCtx->result),
                     xmlSecBufferGetSize(encCtx->result), 1,
                     output);
        fprintf(output, "\n== Result - end buffer\n");
    }
}

/**
 * xmlSecEncCtxDebugXmlDump:
 * @encCtx:             the pointer to <enc:EncryptedData/> processing context.
 * @output:             the pointer to output FILE.
 *
 * Prints the debug information about @encCtx to @output in XML format.
 */
void
xmlSecEncCtxDebugXmlDump(xmlSecEncCtxPtr encCtx, FILE* output) {
    xmlSecAssert(encCtx != NULL);
    xmlSecAssert(output != NULL);

    switch(encCtx->mode) {
        case xmlEncCtxModeEncryptedData:
            if(encCtx->operation == xmlSecTransformOperationEncrypt) {
                fprintf(output, "<DataEncryptionContext ");
            } else {
                fprintf(output, "<DataDecryptionContext ");
            }
            break;
        case xmlEncCtxModeEncryptedKey:
            if(encCtx->operation == xmlSecTransformOperationEncrypt) {
                fprintf(output, "<KeyEncryptionContext ");
            } else {
                fprintf(output, "<KeyDecryptionContext ");
            }
            break;
    }
    fprintf(output, "status=\"%s\" >\n", (encCtx->resultReplaced) ? "replaced" : "not-replaced" );

    fprintf(output, "<Flags>%08x</Flags>\n", encCtx->flags);
    fprintf(output, "<Flags2>%08x</Flags2>\n", encCtx->flags2);

    fprintf(output, "<Id>");
    xmlSecPrintXmlString(output, encCtx->id);
    fprintf(output, "</Id>");

    fprintf(output, "<Type>");
    xmlSecPrintXmlString(output, encCtx->type);
    fprintf(output, "</Type>");

    fprintf(output, "<MimeType>");
    xmlSecPrintXmlString(output, encCtx->mimeType);
    fprintf(output, "</MimeType>");

    fprintf(output, "<Encoding>");
    xmlSecPrintXmlString(output, encCtx->encoding);
    fprintf(output, "</Encoding>");

    fprintf(output, "<Recipient>");
    xmlSecPrintXmlString(output, encCtx->recipient);
    fprintf(output, "</Recipient>");

    fprintf(output, "<CarriedKeyName>");
    xmlSecPrintXmlString(output, encCtx->carriedKeyName);
    fprintf(output, "</CarriedKeyName>");

    fprintf(output, "<KeyInfoReadCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(encCtx->keyInfoReadCtx), output);
    fprintf(output, "</KeyInfoReadCtx>\n");

    fprintf(output, "<KeyInfoWriteCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(encCtx->keyInfoWriteCtx), output);
    fprintf(output, "</KeyInfoWriteCtx>\n");

    fprintf(output, "<EncryptionTransformCtx>\n");
    xmlSecTransformCtxDebugXmlDump(&(encCtx->transformCtx), output);
    fprintf(output, "</EncryptionTransformCtx>\n");

    if(encCtx->encMethod != NULL) {
        fprintf(output, "<EncryptionMethod>\n");
        xmlSecTransformDebugXmlDump(encCtx->encMethod, output);
        fprintf(output, "</EncryptionMethod>\n");
    }

    if(encCtx->encKey != NULL) {
        fprintf(output, "<EncryptionKey>\n");
        xmlSecKeyDebugXmlDump(encCtx->encKey, output);
        fprintf(output, "</EncryptionKey>\n");
    }

    if((encCtx->result != NULL) &&
       (xmlSecBufferGetData(encCtx->result) != NULL) &&
       (encCtx->resultBase64Encoded != 0)) {

        fprintf(output, "<Result>");
        (void)fwrite(xmlSecBufferGetData(encCtx->result),
                     xmlSecBufferGetSize(encCtx->result), 1,
                     output);
        fprintf(output, "</Result>\n");
    }

    switch(encCtx->mode) {
        case xmlEncCtxModeEncryptedData:
            if(encCtx->operation == xmlSecTransformOperationEncrypt) {
                fprintf(output, "</DataEncryptionContext>\n");
            } else {
                fprintf(output, "</DataDecryptionContext>\n");
            }
            break;
        case xmlEncCtxModeEncryptedKey:
            if(encCtx->operation == xmlSecTransformOperationEncrypt) {
                fprintf(output, "</KeyEncryptionContext>\n");
            } else {
                fprintf(output, "</KeyDecryptionContext>\n");
            }
            break;
    }
}

/****************************************************************************************
 *
 * Generate key (used in DerivedKey and AgreementMethod nodes processing)
 *
 ***************************************************************************************/

static xmlSecKeyPtr
xmlSecEncCtxGenerateKey(xmlSecEncCtxPtr encCtx, xmlSecKeyDataId keyId, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyPtr key;
    xmlSecByte * keyData;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(encCtx != NULL, NULL);
    xmlSecAssert2(encCtx->encMethod != NULL, NULL);
    xmlSecAssert2(encCtx->result == NULL, NULL);

    /* we only support binary keys for now */
    ret = xmlSecTransformCtxBinaryExecute(&(encCtx->transformCtx), NULL, 0);
    if((ret < 0) || (encCtx->transformCtx.result == NULL)) {
        xmlSecInternalError("xmlSecTransformCtxBinaryExecute", xmlSecTransformGetName(encCtx->encMethod));
        return(NULL);
    }
    encCtx->result = encCtx->transformCtx.result;

    keyData = xmlSecBufferGetData(encCtx->result);
    keySize = xmlSecBufferGetSize(encCtx->result);
    if((keyData == NULL) || (keySize <= 0)) {
        xmlSecInternalError("xmlSecTransformCtxBinaryExecute(no data)", xmlSecTransformGetName(encCtx->encMethod));
        return(NULL);
    }

    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", xmlSecTransformGetName(encCtx->encMethod));
        return(NULL);
    }

    ret = xmlSecKeyDataBinRead(keyId, key, keyData, keySize, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyDataBinRead",
                            xmlSecKeyDataKlassGetName(keyId));
        xmlSecKeyDestroy(key);
        return(NULL);
    }

    /* success */
    return(key);
}

/**
 * xmlSecEncCtxDerivedKeyGenerate:
 * @encCtx:             the pointer to encryption processing context.
 * @keyId:              the expected key id, the actual derived key might have a different id.
 * @node:               the pointer to <enc11:DerivedKey> node.
 * @keyInfoCtx:         the pointer to the "parent" key info context.
 *
 * Generates (derives) key from @node (https://www.w3.org/TR/xmlenc-core1/#sec-DerivedKey):
 *
 *  <element name="DerivedKey" type="xenc11:DerivedKeyType"/>
 *  <complexType name="DerivedKeyType">
 *      <sequence>
 *          <element ref="xenc11:KeyDerivationMethod" minOccurs="0"/>
 *          <element ref="xenc:ReferenceList" minOccurs="0"/>
 *          <element name="DerivedKeyName" type="string" minOccurs="0"/>
 *          <element name="MasterKeyName" type="string" minOccurs="0"/>
 *      </sequence>
 *      <attribute name="Recipient" type="string" use="optional"/>
 *      <attribute name="Id" type="ID" use="optional"/>
 *      <attribute name="Type" type="anyURI" use="optional"/>
 *  </complexType>
 *
 *  <element name="KeyDerivationMethod" type="xenc:KeyDerivationMethodType"/>
 *  <complexType name="KeyDerivationMethodType">
 *      <sequence>
 *          <any namespace="##any" minOccurs="0" maxOccurs="unbounded"/>
 *      </sequence>
 *      <attribute name="Algorithm" type="anyURI" use="required"/>
 * </complexType>
 *
 * Returns: the derived key on success or NULL  if an error occurs.
 */
xmlSecKeyPtr
xmlSecEncCtxDerivedKeyGenerate(xmlSecEncCtxPtr encCtx, xmlSecKeyDataId keyId, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlNodePtr cur;
    xmlChar* masterKeyName = NULL;
    xmlChar* derivedKeyName = NULL;
    xmlSecKeyPtr key = NULL;
    xmlSecKeyPtr res = NULL;
    int ret;

    xmlSecAssert2(encCtx != NULL, NULL);
    xmlSecAssert2(encCtx->encMethod == NULL, NULL);
    xmlSecAssert2(node != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    /* initialize context and add ID atributes to the list of known ids */
    encCtx->operation = keyInfoCtx->operation;
    xmlSecAddIDs(node->doc, node, xmlSecEncIds);

    /* first read the children */
    cur = xmlSecGetNextElementNode(node->children);

    /* TODO: read the Type attribute as a hint for the desired key type / size
     * (https://github.com/lsh123/xmlsec/issues/515) */

    /* KeyDerivationMethod is an optional element that describes the key derivation algorithm applied to the master (underlying)
     * key material. If the element is absent, the key derivation algorithm must be known by the recipient or the recipient's key
     * derivation will fail.
     *
     * We don't have a pre-defined kd algorithm, so if KDM node is missing, we fail.
     * Algorithm IS REQUIRED.
     */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeKeyDerivationMethod, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeKeyDerivationMethod, NULL);
        goto done;
    }

    encCtx->encMethod = xmlSecTransformCtxNodeRead(&(encCtx->transformCtx), cur, xmlSecTransformUsageKeyDerivationMethod);
    if(encCtx->encMethod == NULL) {
        xmlSecInternalError("xmlSecTransformCtxNodeRead", xmlSecNodeGetName(cur));
        goto done;
    }
    /* expected key size is determined by the requirements from the uplevel key info */
    encCtx->encMethod->expectedOutputSize = keyInfoCtx->keyReq.keyBitsSize / 8;
    encCtx->encMethod->operation = encCtx->operation;
    encCtx->keyInfoReadCtx.operation = encCtx->operation;
    encCtx->keyInfoWriteCtx.operation = encCtx->operation;

    /* next node */
    cur = xmlSecGetNextElementNode(cur->next);

    /* second node is optional ReferenceList, simply skip it for now */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeReferenceList, xmlSecEncNs))) {
        /* next node */
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* third node is optional DerivedKeyName */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDerivedKeyName, xmlSecEnc11Ns))) {
        derivedKeyName = xmlNodeGetContent(cur);
        if(derivedKeyName == NULL) {
            xmlSecInvalidNodeContentError(cur, NULL, "empty");
            goto done;
        }

        /* next node */
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* forth node is optional MasterKeyName */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeMasterKeyName, xmlSecEnc11Ns))) {
        masterKeyName = xmlNodeGetContent(cur);
        if(masterKeyName == NULL) {
            xmlSecInvalidNodeContentError(cur, NULL, "empty");
            goto done;
        }
        /* next node */
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* if there is something left than it's an error */
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        goto done;
    }

    /* get master key */
    ret = xmlSecTransformSetKeyReq(encCtx->encMethod, &(encCtx->keyInfoReadCtx.keyReq));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformSetKeyReq", xmlSecTransformGetName(encCtx->encMethod));
        goto done;
    }
    if((encCtx->encKey == NULL) && (encCtx->keyInfoReadCtx.keysMngr != NULL)) {
        encCtx->encKey = xmlSecKeysMngrFindKey(encCtx->keyInfoReadCtx.keysMngr, masterKeyName, &(encCtx->keyInfoReadCtx));
    }
    if((encCtx->encKey == NULL) || (!xmlSecKeyMatch(encCtx->encKey, NULL, &(encCtx->keyInfoReadCtx.keyReq)))) {
        xmlSecOtherError2(XMLSEC_ERRORS_R_KEY_NOT_FOUND, NULL,
            "encMethod=%s", xmlSecErrorsSafeString(xmlSecTransformGetName(encCtx->encMethod)));
        return(NULL);
    }
    ret = xmlSecTransformSetKey(encCtx->encMethod, encCtx->encKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformSetKey", xmlSecTransformGetName(encCtx->encMethod));
        return(NULL);
    }

    /* let's get the derive key! */
    key = xmlSecEncCtxGenerateKey(encCtx, keyId, keyInfoCtx);
    if(key == NULL) {
        xmlSecInternalError("xmlSecEncCtxGenerateKey", NULL);
        goto done;
    }

    /* set the key name if we have one */
    if(derivedKeyName != NULL) {
        ret = xmlSecKeySetName(key, derivedKeyName);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeySetName", NULL);
            goto done;
        }
    }

    /* success */
    res = key;
    key = NULL;

done:
    if(masterKeyName != NULL) {
        xmlFree(masterKeyName);
    }
    if(derivedKeyName != NULL) {
        xmlFree(derivedKeyName);
    }
    if(key != NULL) {
        xmlSecKeyDestroy(key);
    }
    return(res);
}

/**
 * xmlSecEncCtxAgreementMethodGenerate:
 * @encCtx:             the pointer to encryption processing context.
 * @keyId:              the expected key id, the actual derived key might have a different id.
 * @node:               the pointer to <enc:AgreementMethod> node.
 * @keyInfoCtx:         the pointer to the "parent" key info context.
 *
 * Generates (derives) key from @node (https://www.w3.org/TR/xmlenc-core1/#sec-AgreementMethod):
 *
 *  <element name="AgreementMethod" type="xenc:AgreementMethodType"/>
 *  <complexType name="AgreementMethodType" mixed="true">
 *      <sequence>
 *          <element name="KA-Nonce" minOccurs="0" type="base64Binary"/>
 *          <!-- <element ref="ds:DigestMethod" minOccurs="0"/> -->
 *          <any namespace="##other" minOccurs="0" maxOccurs="unbounded"/>
 *          <element name="OriginatorKeyInfo" minOccurs="0" type="ds:KeyInfoType"/>
 *          <element name="RecipientKeyInfo" minOccurs="0" type="ds:KeyInfoType"/>
 *      </sequence>
 *      <attribute name="Algorithm" type="anyURI" use="required"/>
 *  </complexType>
 *
 * Returns: the generated key on success or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecEncCtxAgreementMethodGenerate(xmlSecEncCtxPtr encCtx, xmlSecKeyDataId keyId, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyPtr key;

    xmlSecAssert2(encCtx != NULL, NULL);
    xmlSecAssert2(encCtx->encMethod == NULL, NULL);
    xmlSecAssert2(node != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    /* initialize context and add ID atributes to the list of known ids */
    encCtx->operation = keyInfoCtx->operation;
    xmlSecAddIDs(node->doc, node, xmlSecEncIds);

    /* the AgreementMethod node is the transform node itself */
    encCtx->transformCtx.parentKeyInfoCtx = keyInfoCtx;
    encCtx->encMethod = xmlSecTransformCtxNodeRead(&(encCtx->transformCtx), node, xmlSecTransformUsageAgreementMethod);
    if(encCtx->encMethod == NULL) {
        xmlSecInternalError("xmlSecTransformCtxNodeRead", xmlSecNodeGetName(node));
        return(NULL);
    }

    /* expected key size is determined by the requirements from the uplevel key info */
    encCtx->encMethod->expectedOutputSize = keyInfoCtx->keyReq.keyBitsSize / 8;
    encCtx->encMethod->operation = encCtx->operation;
    encCtx->keyInfoReadCtx.operation = encCtx->operation;
    encCtx->keyInfoWriteCtx.operation = encCtx->operation;

    /* ecdh transform doesn't require a key, skip SetKeyReq(), FindKey(), and SetKey() */

    /* let's generate the key! */
    key = xmlSecEncCtxGenerateKey(encCtx, keyId, keyInfoCtx);
    if(key == NULL) {
        xmlSecInternalError("xmlSecEncCtxGenerateKey", NULL);
        return(NULL);
    }

    /* success */
    return(key);
}

int
xmlSecEncCtxAgreementMethodXmlWrite(xmlSecEncCtxPtr encCtx, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    int ret;

    xmlSecAssert2(encCtx != NULL, -1);
    xmlSecAssert2(encCtx->encMethod == NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* initialize context and add ID atributes to the list of known ids */
    encCtx->operation = keyInfoCtx->operation;
    xmlSecAddIDs(node->doc, node, xmlSecEncIds);

    /* the AgreementMethod node is the transform node itself */
    encCtx->transformCtx.parentKeyInfoCtx = keyInfoCtx;
    encCtx->encMethod = xmlSecTransformCtxNodeRead(&(encCtx->transformCtx), node, xmlSecTransformUsageAgreementMethod);
    if(encCtx->encMethod == NULL) {
        xmlSecInternalError("xmlSecTransformCtxNodeRead", xmlSecNodeGetName(node));
        return(-1);
    }

    /* write */
    if(encCtx->encMethod->id->writeNode != NULL) {
        ret = encCtx->encMethod->id->writeNode(encCtx->encMethod, node, &(encCtx->transformCtx));
        if(ret < 0) {
            xmlSecInternalError("writeNode", xmlSecNodeGetName(node));
            return(-1);
        }
    }

    return(0);
}

#endif /* XMLSEC_NO_XMLENC */
