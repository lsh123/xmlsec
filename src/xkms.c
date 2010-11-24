/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * "XML Key Management Specification v 2.0" implementation
 *  http://www.w3.org/TR/xkms2/
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_XKMS

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
#include <xmlsec/soap.h>
#include <xmlsec/xkms.h>
#include <xmlsec/private.h>
#include <xmlsec/private/xkms.h>
#include <xmlsec/errors.h>

#define XMLSEC_XKMS_ID_ATTRIBUTE_LEN            32

/* The ID attribute in XKMS is 'Id' */
static const xmlChar* xmlSecXkmsServerIds[] = { BAD_CAST "Id", NULL };

#ifndef XMLSEC_NO_SOAP
static int      xmlSecXkmsServerCtxWriteSoap11FatalError        (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr envNode);
static int      xmlSecXkmsServerCtxWriteSoap12FatalError        (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr envNode);
#endif /* XMLSEC_NO_SOAP */

static int      xmlSecXkmsServerCtxRequestAbstractTypeNodeRead  (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr* node);
static int      xmlSecXkmsServerCtxSignatureNodeRead            (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static int      xmlSecXkmsServerCtxMessageExtensionNodesRead    (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr* node);
static int      xmlSecXkmsServerCtxOpaqueClientDataNodeRead     (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static int      xmlSecXkmsServerCtxPendingNotificationNodeRead  (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static int      xmlSecXkmsServerCtxRespondWithNodesRead         (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr* node);
static int      xmlSecXkmsServerCtxPendingRequestNodeRead       (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr* node);
static int      xmlSecXkmsServerCtxQueryKeyBindingNodeRead      (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static int      xmlSecXkmsServerCtxKeyBindingAbstractTypeNodeRead(xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr* node);
static int      xmlSecXkmsServerCtxKeyBindingAbstractTypeNodeWrite(xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyPtr key);
static int      xmlSecXkmsServerCtxKeyInfoNodeWrite             (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyPtr key);
static int      xmlSecXkmsServerCtxUseKeyWithNodesRead          (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr* node);
static int      xmlSecXkmsServerCtxUseKeyWithNodesWrite         (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyPtr key);
static int      xmlSecXkmsServerCtxTimeInstantNodeRead          (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static int      xmlSecXkmsServerCtxResultTypeNodeWrite          (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static int      xmlSecXkmsServerCtxRequestSignatureValueNodeWrite(xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static int      xmlSecXkmsServerCtxUnverifiedKeyBindingNodeWrite(xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyPtr key);
static int      xmlSecXkmsServerCtxKeyBindingNodeWrite          (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyPtr key);
static int      xmlSecXkmsServerCtxValidityIntervalNodeWrite    (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyPtr key);
static int      xmlSecXkmsServerCtxKeyBindingStatusNodeWrite    (xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyPtr key);


static const xmlSecQName2IntegerInfo gXmlSecXkmsResultMajorInfo[] =
{
  { xmlSecXkmsNs, xmlSecResultMajorCodeSuccess,
    xmlSecXkmsResultMajorSuccess },
  { xmlSecXkmsNs, xmlSecResultMajorCodeVersionMismatch,
    xmlSecXkmsResultMajorVersionMismatch },
  { xmlSecXkmsNs, xmlSecResultMajorCodeSender,
    xmlSecXkmsResultMajorSender },
  { xmlSecXkmsNs, xmlSecResultMajorCodeReceiver,
    xmlSecXkmsResultMajorReceiver },
  { xmlSecXkmsNs, xmlSecResultMajorCodeRepresent,
    xmlSecXkmsResultMajorRepresent },
  { xmlSecXkmsNs, xmlSecResultMajorCodePending,
    xmlSecXkmsResultMajorPending, },
  { NULL , NULL, 0 }    /* MUST be last in the list */
};

static const xmlSecQName2IntegerInfo gXmlSecXkmsMinorErrorInfo[] =
{
  { xmlSecXkmsNs, xmlSecResultMinorCodeNoMatch,
    xmlSecXkmsResultMinorNoMatch },
  { xmlSecXkmsNs, xmlSecResultMinorCodeTooManyResponses,
    xmlSecXkmsResultMinorTooManyResponses },
  { xmlSecXkmsNs, xmlSecResultMinorCodeIncomplete,
    xmlSecXkmsResultMinorIncomplete },
  { xmlSecXkmsNs, xmlSecResultMinorCodeFailure,
    xmlSecXkmsResultMinorFailure },
  { xmlSecXkmsNs, xmlSecResultMinorCodeRefused,
    xmlSecXkmsResultMinorRefused },
  { xmlSecXkmsNs, xmlSecResultMinorCodeNoAuthentication,
    xmlSecXkmsResultMinorNoAuthentication },
  { xmlSecXkmsNs, xmlSecResultMinorCodeMessageNotSupported,
    xmlSecXkmsResultMinorMessageNotSupported },
  { xmlSecXkmsNs, xmlSecResultMinorCodeUnknownResponseId,
    xmlSecXkmsResultMinorUnknownResponseId },
  { xmlSecXkmsNs, xmlSecResultMinorCodeNotSynchronous,
    xmlSecXkmsResultMinorSynchronous },
  { NULL, NULL, 0 }     /* MUST be last in the list */
};

static const xmlSecQName2IntegerInfo gXmlSecXkmsKeyBindingStatusInfo[] =
{
  { xmlSecXkmsNs, xmlSecKeyBindingStatusValid,
    xmlSecXkmsKeyBindingStatusValid },
  { xmlSecXkmsNs, xmlSecKeyBindingStatusInvalid,
    xmlSecXkmsKeyBindingStatusInvalid },
  { xmlSecXkmsNs, xmlSecKeyBindingStatusIndeterminate,
    xmlSecXkmsKeyBindingStatusIndeterminate },
  { NULL, NULL, 0 }     /* MUST be last in the list */
};

static const xmlSecQName2BitMaskInfo gXmlSecXkmsKeyUsageInfo[] =
{
  { xmlSecXkmsNs, xmlSecKeyUsageEncryption,
    xmlSecKeyUsageEncrypt | xmlSecKeyUsageDecrypt },
  { xmlSecXkmsNs, xmlSecKeyUsageSignature,
    xmlSecKeyUsageSign | xmlSecKeyUsageVerify },
  { xmlSecXkmsNs, xmlSecKeyUsageExchange,
    xmlSecKeyUsageKeyExchange},
  { NULL, NULL, 0 }     /* MUST be last in the list */
};

static const xmlSecQName2BitMaskInfo gXmlSecXkmsKeyBindingReasonInfo[] =
{
    { xmlSecXkmsNs, xmlSecKeyBindingReasonIssuerTrust,
      XMLSEC_XKMS_KEY_BINDING_REASON_MASK_ISSUER_TRAST },
    { xmlSecXkmsNs, xmlSecKeyBindingReasonRevocationStatus,
      XMLSEC_XKMS_KEY_BINDING_REASON_MASK_REVOCATION_STATUS },
    { xmlSecXkmsNs, xmlSecKeyBindingReasonValidityInterval,
      XMLSEC_XKMS_KEY_BINDING_REASON_MASK_VALIDITY_INTERVAL },
    { xmlSecXkmsNs, xmlSecKeyBindingReasonSignature,
      XMLSEC_XKMS_KEY_BINDING_REASON_MASK_SIGNATURE },
    { NULL, NULL, 0 }   /* MUST be last in the list */
};

static const xmlSecQName2BitMaskInfo gXmlSecXkmsResponseMechanismInfo[] =
{
    { xmlSecXkmsNs, xmlSecResponseMechanismRepresent,
      XMLSEC_XKMS_RESPONSE_MECHANISM_MASK_REPRESENT },
    { xmlSecXkmsNs, xmlSecResponseMechanismPending,
      XMLSEC_XKMS_RESPONSE_MECHANISM_MASK_PENDING },
    { xmlSecXkmsNs, xmlSecResponseMechanismRequestSignatureValue,
      XMLSEC_XKMS_RESPONSE_MECHANISM_MASK_REQUEST_SIGNATURE_VALUE },
    { NULL, NULL, 0 }   /* MUST be last in the list */
};

static const xmlSecQName2IntegerInfo gXmlSecXkmsFormatInfo[] =
{
  { NULL, xmlSecXkmsFormatStrPlain,
    xmlSecXkmsServerFormatPlain },
#ifndef XMLSEC_NO_SOAP
  { NULL, xmlSecXkmsFormatStrSoap11,
    xmlSecXkmsServerFormatSoap11 },
  { NULL, xmlSecXkmsFormatStrSoap12,
    xmlSecXkmsServerFormatSoap12 },
#endif /* XMLSEC_NO_SOAP */
  { NULL, NULL, 0 }     /* MUST be last in the list */
};

/**
 * xmlSecXkmsServerFormatFromString:
 * @str         the string.
 *
 * Gets xmlSecXkmsServerFormat from string @str.
 *
 * Returns: corresponding format or xmlSecXkmsServerFormatUnknown
 * if format could not be recognized.
 */
xmlSecXkmsServerFormat
xmlSecXkmsServerFormatFromString(const xmlChar* str) {
    int res;
    int ret;

    xmlSecAssert2(str != NULL, xmlSecXkmsServerFormatUnknown);

    ret = xmlSecQName2IntegerGetInteger(gXmlSecXkmsFormatInfo, NULL, str, &res);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecQName2IntegerGetInteger",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecXkmsServerFormatUnknown);
    }

    return((xmlSecXkmsServerFormat)res);
}

/**
 * xmlSecXkmsServerFormatToString:
 * @format:     the format.
 *
 * Gets string from @format.
 *
 * Returns: string corresponding to @format or NULL if an error occurs.
 */
const xmlChar*
xmlSecXkmsServerFormatToString (xmlSecXkmsServerFormat format) {
    xmlSecQName2IntegerInfoConstPtr info;

    xmlSecAssert2(format != xmlSecXkmsServerFormatUnknown, NULL);

    info = xmlSecQName2IntegerGetInfo(gXmlSecXkmsFormatInfo, format);
    if(info == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecQName2IntegerGetInfo",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(NULL);
    }
    return(info->qnameLocalPart);
}

/**
 * xmlSecXkmsServerCtxCreate:
 * @keysMngr:   the pointer to keys manager.
 *
 * Creates XKMS request server side processing context.
 * The caller is responsible for destroying returned object by calling
 * #xmlSecXkmsServerCtxDestroy function.
 *
 * Returns: pointer to newly allocated context object or NULL if an error
 * occurs.
 */
xmlSecXkmsServerCtxPtr
xmlSecXkmsServerCtxCreate(xmlSecKeysMngrPtr keysMngr) {
    xmlSecXkmsServerCtxPtr ctx;
    int ret;

    ctx = (xmlSecXkmsServerCtxPtr) xmlMalloc(sizeof(xmlSecXkmsServerCtx));
    if(ctx == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_MALLOC_FAILED,
                    "sizeof(xmlSecXkmsServerCtx)=%d",
                    sizeof(xmlSecXkmsServerCtx));
        return(NULL);
    }

    ret = xmlSecXkmsServerCtxInitialize(ctx, keysMngr);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxInitialize",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        xmlSecXkmsServerCtxDestroy(ctx);
        return(NULL);
    }
    return(ctx);
}

/**
 * xmlSecXkmsServerCtxDestroy:
 * @ctx:        the pointer to XKMS processing context.
 *
 * Destroy context object created with #xmlSecXkmsServerCtxCreate function.
 */
void
xmlSecXkmsServerCtxDestroy(xmlSecXkmsServerCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    xmlSecXkmsServerCtxFinalize(ctx);
    xmlFree(ctx);
}

/**
 * xmlSecXkmsServerCtxInitialize:
 * @ctx:        the pointer to XKMS processing context.
 * @keysMngr:   the pointer to keys manager.
 *
 * Initializes XKMS element processing context.
 * The caller is responsible for cleaning up returned object by calling
 * #xmlSecXkmsServerCtxFinalize function.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecXkmsServerCtxInitialize(xmlSecXkmsServerCtxPtr ctx, xmlSecKeysMngrPtr keysMngr) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecXkmsServerCtx));

    ctx->resultMajor    = xmlSecXkmsResultMajorSuccess;
    ctx->resultMinor    = xmlSecXkmsResultMinorNone;
    ctx->responseLimit  = XMLSEC_XKMS_NO_RESPONSE_LIMIT;
    ctx->idLen          = XMLSEC_XKMS_ID_ATTRIBUTE_LEN;

    /* initialize key info */
    ret = xmlSecKeyInfoCtxInitialize(&(ctx->keyInfoReadCtx), keysMngr);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecKeyInfoCtxInitialize",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    ctx->keyInfoReadCtx.mode = xmlSecKeyInfoModeRead;

    ret = xmlSecKeyInfoCtxInitialize(&(ctx->keyInfoWriteCtx), keysMngr);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecKeyInfoCtxInitialize",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    ctx->keyInfoWriteCtx.mode = xmlSecKeyInfoModeWrite;

    /* enabled RespondWith */
    ret = xmlSecPtrListInitialize(&(ctx->enabledRespondWithIds), xmlSecXkmsRespondWithIdListId);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecPtrListInitialize",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* enabled ServerRequest */
    ret = xmlSecPtrListInitialize(&(ctx->enabledServerRequestIds), xmlSecXkmsServerRequestIdListId);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecPtrListInitialize",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }



    /* initialize keys list */
    ret = xmlSecPtrListInitialize(&(ctx->keys), xmlSecKeyPtrListId);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecPtrListInitialize",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* initialize RespondWith list */
    ret = xmlSecPtrListInitialize(&(ctx->respWithList), xmlSecXkmsRespondWithIdListId);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecPtrListInitialize",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecXkmsServerCtxFinalize:
 * @ctx:        the pointer to XKMS processing context.
 *
 * Cleans up @ctx object.
 */
void
xmlSecXkmsServerCtxFinalize(xmlSecXkmsServerCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    xmlSecXkmsServerCtxReset(ctx);

    if(ctx->expectedService != NULL) {
        xmlFree(ctx->expectedService);
    }
    if(ctx->idPrefix != NULL) {
        xmlFree(ctx->idPrefix);
    }

    xmlSecKeyInfoCtxFinalize(&(ctx->keyInfoReadCtx));
    xmlSecKeyInfoCtxFinalize(&(ctx->keyInfoWriteCtx));
    xmlSecPtrListFinalize(&(ctx->enabledRespondWithIds));
    xmlSecPtrListFinalize(&(ctx->enabledServerRequestIds));
    xmlSecPtrListFinalize(&(ctx->keys));
    xmlSecPtrListFinalize(&(ctx->respWithList));
    memset(ctx, 0, sizeof(xmlSecXkmsServerCtx));
}

/**
 * xmlSecXkmsServerCtxReset:
 * @ctx:        the pointer to XKMS processing context.
 *
 * Resets @ctx object, user settings are not touched.
 */
void
xmlSecXkmsServerCtxReset(xmlSecXkmsServerCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    ctx->resultMajor = xmlSecXkmsResultMajorSuccess;
    ctx->resultMinor = xmlSecXkmsResultMinorNone;
    xmlSecKeyInfoCtxReset(&(ctx->keyInfoReadCtx));
    xmlSecKeyInfoCtxReset(&(ctx->keyInfoWriteCtx));
    xmlSecPtrListEmpty(&(ctx->keys));
    xmlSecPtrListEmpty(&(ctx->respWithList));

    ctx->requestNode            = NULL;
    ctx->opaqueClientDataNode   = NULL;
    ctx->firtsMsgExtNode        = NULL;
    ctx->keyInfoNode            = NULL;
    ctx->requestId              = xmlSecXkmsServerRequestIdUnknown;

    if(ctx->id != NULL) {
        xmlFree(ctx->id); ctx->id = NULL;
    }
    if(ctx->service != NULL) {
        xmlFree(ctx->service); ctx->service = NULL;
    }
    if(ctx->nonce != NULL) {
        xmlFree(ctx->nonce); ctx->nonce = NULL;
    }
    if(ctx->originalRequestId != NULL) {
        xmlFree(ctx->originalRequestId); ctx->originalRequestId = NULL;
    }
    if(ctx->pendingNotificationMechanism != NULL) {
        xmlFree(ctx->pendingNotificationMechanism);
        ctx->pendingNotificationMechanism = NULL;
    }
    if(ctx->pendingNotificationIdentifier != NULL) {
        xmlFree(ctx->pendingNotificationIdentifier);
        ctx->pendingNotificationIdentifier = NULL;
    }
    if(ctx->compoundRequestContexts != NULL) {
        xmlSecPtrListDestroy(ctx->compoundRequestContexts);
        ctx->compoundRequestContexts = NULL;
    }

    ctx->responseLimit          = XMLSEC_XKMS_NO_RESPONSE_LIMIT;
    ctx->responseMechanismMask  = 0;
}

/**
 * xmlSecXkmsServerCtxCopyUserPref:
 * @dst:        the pointer to destination context.
 * @src:        the pointer to source context.
 *
 * Copies user preference from @src context to @dst.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecXkmsServerCtxCopyUserPref(xmlSecXkmsServerCtxPtr dst, xmlSecXkmsServerCtxPtr src) {
    int ret;

    xmlSecAssert2(dst != NULL, -1);
    xmlSecAssert2(src != NULL, -1);

    dst->userData       = src->userData;
    dst->flags          = src->flags;
    dst->flags2         = src->flags2;

    ret = xmlSecKeyInfoCtxCopyUserPref(&(dst->keyInfoReadCtx), &(src->keyInfoReadCtx));
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecKeyInfoCtxCopyUserPref",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    ret = xmlSecKeyInfoCtxCopyUserPref(&(dst->keyInfoWriteCtx), &(src->keyInfoWriteCtx));
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecKeyInfoCtxCopyUserPref",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    if(src->expectedService != NULL) {
        dst->expectedService = xmlStrdup(src->expectedService);
        if(dst->expectedService == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlStrdup",
                        XMLSEC_ERRORS_R_MALLOC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    }

    if(src->idPrefix != NULL) {
        dst->idPrefix = xmlStrdup(src->idPrefix);
        if(dst->idPrefix == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlStrdup",
                        XMLSEC_ERRORS_R_MALLOC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    }
    src->idLen = dst->idLen;


    ret = xmlSecPtrListCopy(&(dst->enabledRespondWithIds), &(src->enabledRespondWithIds));
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecPtrListCopy",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    ret = xmlSecPtrListCopy(&(dst->enabledServerRequestIds), &(src->enabledServerRequestIds));
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecPtrListCopy",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecXkmsServerCtxProcess:
 * @ctx:        the pointer to XKMS processing context.
 * @node:       the pointer to request node.
 * @format:     the request/response format.
 * @doc:        the pointer to response parent XML document (might be NULL).
 *
 * Reads XKMS request from @node and creates response to a newly created node.
 * Caller is responsible for adding the returned node to the XML document.
 *
 * Returns: pointer to newly created XKMS response node or NULL
 * if an error occurs.
 */
xmlNodePtr
xmlSecXkmsServerCtxProcess(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node,
                              xmlSecXkmsServerFormat format, xmlDocPtr doc) {
    int ret;

    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->requestId == NULL, NULL);
    xmlSecAssert2(ctx->requestNode == NULL, NULL);
    xmlSecAssert2(node != NULL, NULL);

    ctx->requestNode = xmlSecXkmsServerCtxRequestUnwrap(ctx, node, format);
    if(ctx->requestNode == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxRequestUnwrap",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "node=%s",
                    xmlSecErrorsSafeString(node->name));
        xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
        goto done;
    }

    ret = xmlSecXkmsServerCtxRequestRead(ctx, ctx->requestNode);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerRequestIdListFindByNode",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "ctx->requestNode=%s",
                    xmlSecErrorsSafeString(ctx->requestNode->name));
        xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
        goto done;
    }

    ret = xmlSecXkmsServerRequestExecute(ctx->requestId, ctx);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerRequestExecute",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "ctx->requestNode=%s",
                    xmlSecErrorsSafeString(ctx->requestNode->name));
        xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
        goto done;
    }

done:
    /* always try to write response back */
    if(ctx->requestId != NULL) {
        xmlNodePtr respNode;
        xmlNodePtr wrappedRespNode;

        respNode = xmlSecXkmsServerCtxResponseWrite(ctx, doc);
        if(respNode == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecXkmsServerCtxResponseWrite",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "ctx->requestNode=%s",
                        xmlSecErrorsSafeString(ctx->requestNode->name));
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            goto error;
        }


        wrappedRespNode = xmlSecXkmsServerCtxResponseWrap(ctx, respNode, format, doc);
        if(wrappedRespNode == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecXkmsServerCtxResponseWrite",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "ctx->requestNode=%s",
                        xmlSecErrorsSafeString(ctx->requestNode->name));
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            xmlFreeNode(respNode);
            goto error;
        }

        return(wrappedRespNode);
    }

error:
    /* last attempt: create fatatl error response */
    return(xmlSecXkmsServerCtxFatalErrorResponseCreate(ctx, format, doc));
}

/**
 * xmlSecXkmsServerCtxRequestRead:
 * @ctx:        the pointer to XKMS processing context.
 * @node:       the pointer to request node.
 *
 * Reads XKMS request from @node and stores data in @ctx.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecXkmsServerCtxRequestRead(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->requestId == NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* find out what the request is */
    if(xmlSecPtrListGetSize(&(ctx->enabledServerRequestIds)) > 0) {
        ctx->requestId = xmlSecXkmsServerRequestIdListFindByNode(&(ctx->enabledServerRequestIds), node);
    } else {
        ctx->requestId = xmlSecXkmsServerRequestIdListFindByNode(xmlSecXkmsServerRequestIdsGet(), node);
    }
    if(ctx->requestId == xmlSecXkmsServerRequestIdUnknown) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerRequestIdListFindByNode",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "node=%s",
                    xmlSecErrorsSafeString(node->name));
        xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorMessageNotSupported);
        return(-1);
    }

    xmlSecAddIDs(node->doc, node, xmlSecXkmsServerIds);
    ret = xmlSecXkmsServerRequestNodeRead(ctx->requestId, ctx, node);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerRequestNodeRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "request=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsServerRequestKlassGetName(ctx->requestId)));
        xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorFailure);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecXkmsServerCtxResponseWrite:
 * @ctx:        the pointer to XKMS processing context.
 * @doc:        the pointer to response parent XML document (might be NULL).
 *
 * Writes XKMS response from context to a newly created node. Caller is
 * responsible for adding the returned node to the XML document.
 *
 * Returns: pointer to newly created XKMS response node or NULL
 * if an error occurs.
 */
xmlNodePtr
xmlSecXkmsServerCtxResponseWrite(xmlSecXkmsServerCtxPtr ctx, xmlDocPtr doc) {
    xmlNodePtr respNode;

    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->requestId != NULL, NULL);

    /* now write results */
    respNode = xmlSecXkmsServerRequestNodeWrite(ctx->requestId, ctx, doc, NULL);
    if(respNode == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerRequestNodeWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "request=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsServerRequestKlassGetName(ctx->requestId)));
        xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
        return(NULL);
    }

    return(respNode);
}

/**
 * xmlSecXkmsServerCtxRequestUnwrap:
 * @ctx:        the pointer to XKMS processing context.
 * @node:       the pointer to request node.
 * @format:     the request/response format.
 *
 * Removes SOAP or other envelope from XKMS request.
 *
 * Returns: pointer to "real" XKMS request node or NULL if an error occurs.
 */
xmlNodePtr
xmlSecXkmsServerCtxRequestUnwrap(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node,  xmlSecXkmsServerFormat format) {
    xmlNodePtr result = NULL;

    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(node != NULL, NULL);

    switch(format) {
    case xmlSecXkmsServerFormatPlain:
        result = node;
        break;
#ifndef XMLSEC_NO_SOAP
    case xmlSecXkmsServerFormatSoap11:
        /* verify that it is actually soap Envelope node */
        if(xmlSecSoap11CheckEnvelope(node) != 1) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecSoap11CheckEnvelope",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorFailure);
            return(NULL);
        }

        /* check that Body has exactly one entry */
        if(xmlSecSoap11GetBodyEntriesNumber(node) != 1) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecSoap11GetBodyEntriesNumber",
                        XMLSEC_ERRORS_R_INVALID_DATA,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorFailure);
            return(NULL);
        }

        /* this one enntry is our xkms request */
        result = xmlSecSoap11GetBodyEntry(node, 0);
        if(result == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecSoap11GetBodyEntry",
                        XMLSEC_ERRORS_R_INVALID_DATA,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorFailure);
            return(NULL);
        }

        break;
    case xmlSecXkmsServerFormatSoap12:
        /* verify that it is actually soap Envelope node */
        if(xmlSecSoap12CheckEnvelope(node) != 1) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecSoap12CheckEnvelope",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorFailure);
            return(NULL);
        }

        /* check that Body has exactly one entry */
        if(xmlSecSoap12GetBodyEntriesNumber(node) != 1) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecSoap12GetBodyEntriesNumber",
                        XMLSEC_ERRORS_R_INVALID_DATA,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorFailure);
            return(NULL);
        }

        /* this one enntry is our xkms request */
        result = xmlSecSoap12GetBodyEntry(node, 0);
        if(result == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecSoap12GetBodyEntry",
                        XMLSEC_ERRORS_R_INVALID_DATA,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorFailure);
            return(NULL);
        }

        break;
#endif /* XMLSEC_NO_SOAP */
    default:
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
                    "format=%d",
                    format);
        xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorFailure);
        return(NULL);
    }

    return(result);
}

/**
 * xmlSecXkmsServerCtxResponseWrap:
 * @ctx:        the pointer to XKMS processing context.
 * @node:       the pointer to response node.
 * @format:     the request/response format.
 * @doc:        the pointer to response parent XML document (might be NULL).
 *
 * Creates SOAP or other envelope around XKMS response.
 * Caller is responsible for adding the returned node to the XML document.
 *
 * Returns: pointer to newly created response envelope node or NULL
 * if an error occurs.
 */
xmlNodePtr
xmlSecXkmsServerCtxResponseWrap(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node, xmlSecXkmsServerFormat format, xmlDocPtr doc) {
    xmlNodePtr result = NULL;

    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(node != NULL, NULL);

    switch(format) {
    case xmlSecXkmsServerFormatPlain:
        result = node; /* do nothing */
        break;
#ifndef XMLSEC_NO_SOAP
    case xmlSecXkmsServerFormatSoap11:
        result = xmlSecSoap11CreateEnvelope(doc);
        if(result == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecSoap11CreateEnvelope",
                        XMLSEC_ERRORS_R_INVALID_DATA,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(NULL);
        }

        if(xmlSecSoap11AddBodyEntry(result, node) == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecSoap11AddBodyEntry",
                        XMLSEC_ERRORS_R_INVALID_DATA,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(NULL);
        }
        break;
    case xmlSecXkmsServerFormatSoap12:
        result = xmlSecSoap12CreateEnvelope(doc);
        if(result == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecSoap12CreateEnvelope",
                        XMLSEC_ERRORS_R_INVALID_DATA,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(NULL);
        }

        if(xmlSecSoap12AddBodyEntry(result, node) == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecSoap12AddBodyEntry",
                        XMLSEC_ERRORS_R_INVALID_DATA,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(NULL);
        }
        break;
#endif /* XMLSEC_NO_SOAP */
    default:
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
                    "format=%d",
                    format);
        xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorFailure);
        return(NULL);
    }

    return(result);
}

/**
 * xmlSecXkmsServerCtxFatalErrorResponseCreate:
 * @ctx:        the pointer to XKMS processing context.
 * @format:     the request/response format.
 * @doc:        the pointer to response parent XML document (might be NULL).
 *
 * Creates a "fatal error" SOAP or other envelope respons. Caller is
 * responsible for adding the returned node to the XML document.
 *
 * Returns: pointer to newly created fatal error response (it might be NULL).
 */
xmlNodePtr
xmlSecXkmsServerCtxFatalErrorResponseCreate(xmlSecXkmsServerCtxPtr ctx, xmlSecXkmsServerFormat format, xmlDocPtr doc) {
    xmlNodePtr result = NULL;
    int ret;

    xmlSecAssert2(ctx != NULL, NULL);

    /* make sure that we have an error */
    if(ctx->resultMajor == xmlSecXkmsResultMajorSuccess) {
        xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
    }

    switch(format) {
    case xmlSecXkmsServerFormatPlain:
        /* try to create fatal error response with XKMS Status request */
        result = xmlSecXkmsServerRequestNodeWrite(xmlSecXkmsServerRequestResultId, ctx, doc, NULL);
        if(result == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecXkmsServerRequestNodeWrite",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(NULL);
        }
        break;
#ifndef XMLSEC_NO_SOAP
    case xmlSecXkmsServerFormatSoap11:
        result = xmlSecSoap11CreateEnvelope(doc);
        if(result == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecSoap11CreateEnvelope",
                        XMLSEC_ERRORS_R_INVALID_DATA,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(NULL);
        }

        ret = xmlSecXkmsServerCtxWriteSoap11FatalError(ctx, result);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecXkmsServerCtxWriteSoap11FatalError",
                        XMLSEC_ERRORS_R_INVALID_DATA,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            xmlFreeNode(result);
            return(NULL);
        }

        break;
    case xmlSecXkmsServerFormatSoap12:
        result = xmlSecSoap12CreateEnvelope(doc);
        if(result == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecSoap12CreateEnvelope",
                        XMLSEC_ERRORS_R_INVALID_DATA,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(NULL);
        }

        ret = xmlSecXkmsServerCtxWriteSoap12FatalError(ctx, result);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecXkmsServerCtxWriteSoap12FatalError",
                        XMLSEC_ERRORS_R_INVALID_DATA,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            xmlFreeNode(result);
            return(NULL);
        }

        break;
#endif /* XMLSEC_NO_SOAP */
    default:
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
                    "format=%d",
                    format);
        xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorFailure);
        return(NULL);
    }

    return(result);
}

#ifndef XMLSEC_NO_SOAP
static int
xmlSecXkmsServerCtxWriteSoap11FatalError(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr envNode) {
    const xmlChar* faultCodeHref = NULL;
    const xmlChar* faultCodeLocalPart = NULL;
    xmlChar* faultString = NULL;
    int len;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(envNode != NULL, -1);

    if((ctx->resultMajor == xmlSecXkmsResultMajorVersionMismatch) ||
       (ctx->requestNode == NULL)) {
        /* we were not able to parse the envelope or its general version mismatch error */
        faultCodeHref = xmlSecSoap11Ns;
        faultCodeLocalPart = xmlSecSoapFaultCodeVersionMismatch;
        faultString = xmlStrdup(xmlSecXkmsSoapFaultReasonUnsupportedVersion);
        if(faultString == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlStrdup",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(-1);
        }
    } else if((ctx->resultMajor == xmlSecXkmsResultMajorSender) &&
              (ctx->requestId == NULL)) {
        /* we understood the request but were not able to parse input message */
        faultCodeHref = xmlSecSoap11Ns;
        faultCodeLocalPart = xmlSecSoapFaultCodeClient;

        len = xmlStrlen(BAD_CAST xmlSecErrorsSafeString(ctx->requestNode->name)) +
              xmlStrlen(xmlSecXkmsSoapFaultReasonMessageInvalid) + 1;
        faultString = xmlMalloc(len + 1);
        if(faultString == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlMalloc",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(-1);
        }
        xmlSecStrPrintf(faultString, len , xmlSecXkmsSoapFaultReasonMessageInvalid,
                        xmlSecErrorsSafeString(ctx->requestNode->name));
    } else if((ctx->resultMajor == xmlSecXkmsResultMajorReceiver) &&
              (ctx->requestId == NULL)) {
        /* we understood the request but were not able to process it */
        faultCodeHref = xmlSecSoap11Ns;
        faultCodeLocalPart = xmlSecSoapFaultCodeServer;
        faultString = xmlStrdup(xmlSecXkmsSoapFaultReasonServiceUnavailable);
        if(faultString == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlStrdup",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(-1);
        }
    } else if((ctx->requestId == NULL) && (ctx->requestNode != NULL)) {
        /* we parsed the envelope but were not able to understand this request */
        faultCodeHref = xmlSecSoap11Ns;
        faultCodeLocalPart = xmlSecSoapFaultCodeClient;

        len = xmlStrlen(BAD_CAST xmlSecErrorsSafeString(ctx->requestNode->name)) +
              xmlStrlen(xmlSecXkmsSoapFaultReasonMessageNotSupported) + 1;
        faultString = xmlMalloc(len + 1);
        if(faultString == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlMalloc",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(-1);
        }
        xmlSecStrPrintf(faultString, len , xmlSecXkmsSoapFaultReasonMessageNotSupported,
                        xmlSecErrorsSafeString(ctx->requestNode->name));
    } else {
        /* just some error */
        faultCodeHref = xmlSecSoap11Ns;
        faultCodeLocalPart = xmlSecSoapFaultCodeServer;
        faultString = xmlStrdup(xmlSecXkmsSoapFaultReasonServiceUnavailable);
        if(faultString == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlStrdup",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(-1);
        }
    }

    if(xmlSecSoap11AddFaultEntry(envNode, faultCodeHref, faultCodeLocalPart, faultString, NULL) == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecSoap11AddFaultEntry",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
        xmlFree(faultString);
        return(-1);
    }

    xmlFree(faultString);
    return(0);
}

static int
xmlSecXkmsServerCtxWriteSoap12FatalError(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr envNode) {
    xmlSecSoap12FaultCode faultCode = xmlSecSoap12FaultCodeUnknown;
    const xmlChar* faultSubCodeHref = NULL;
    const xmlChar* faultSubCodeLocalPart = NULL;
    xmlChar* faultReason = NULL;
    int len;
    xmlNodePtr faultNode;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(envNode != NULL, -1);

    if((ctx->resultMajor == xmlSecXkmsResultMajorVersionMismatch) ||
       (ctx->requestNode == NULL)) {
        /* we were not able to parse the envelope or its general version mismatch error */
        faultCode = xmlSecSoap12FaultCodeVersionMismatch;
        faultReason = xmlStrdup(xmlSecXkmsSoapFaultReasonUnsupportedVersion);
        if(faultReason == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlStrdup",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(-1);
        }
    } else if((ctx->resultMajor == xmlSecXkmsResultMajorSender) &&
              (ctx->requestId == NULL)) {
        /* we understood the request but were not able to parse input message */
        faultCode = xmlSecSoap12FaultCodeSender;
        faultSubCodeHref = xmlSecXkmsNs;
        faultSubCodeLocalPart = xmlSecXkmsSoapSubcodeValueMessageNotSupported;

        len = xmlStrlen(BAD_CAST xmlSecErrorsSafeString(ctx->requestNode->name)) +
              xmlStrlen(xmlSecXkmsSoapFaultReasonMessageInvalid) + 1;
        faultReason = xmlMalloc(len + 1);
        if(faultReason == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlMalloc",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(-1);
        }
        xmlSecStrPrintf(faultReason, len , xmlSecXkmsSoapFaultReasonMessageInvalid,
                        xmlSecErrorsSafeString(ctx->requestNode->name));
    } else if((ctx->resultMajor == xmlSecXkmsResultMajorReceiver) &&
              (ctx->requestId == NULL)) {
        /* we understood the request but were not able to process it */
        faultCode = xmlSecSoap12FaultCodeReceiver;
        faultReason = xmlStrdup(xmlSecXkmsSoapFaultReasonServiceUnavailable);
        if(faultReason == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlStrdup",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(-1);
        }
    } else if((ctx->requestId == NULL) && (ctx->requestNode != NULL)) {
        /* we parsed the envelope but were not able to understand this request */
        faultCode = xmlSecSoap12FaultCodeSender;
        faultSubCodeHref = xmlSecXkmsNs;
        faultSubCodeLocalPart = xmlSecXkmsSoapSubcodeValueBadMessage;

        len = xmlStrlen(BAD_CAST xmlSecErrorsSafeString(ctx->requestNode->name)) +
              xmlStrlen(xmlSecXkmsSoapFaultReasonMessageNotSupported) + 1;
        faultReason = xmlMalloc(len + 1);
        if(faultReason == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlMalloc",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(-1);
        }
        xmlSecStrPrintf(faultReason, len , xmlSecXkmsSoapFaultReasonMessageNotSupported,
                        xmlSecErrorsSafeString(ctx->requestNode->name));
    } else {
        /* just some error */
        faultCode = xmlSecSoap12FaultCodeReceiver;
        faultReason = xmlStrdup(xmlSecXkmsSoapFaultReasonServiceUnavailable);
        if(faultReason == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlStrdup",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
            return(-1);
        }
    }
    xmlSecAssert2(faultCode != xmlSecSoap12FaultCodeUnknown, -1);
    xmlSecAssert2(faultReason != NULL, -1);

    faultNode = xmlSecSoap12AddFaultEntry(envNode, faultCode, faultReason,
                                    xmlSecXkmsSoapFaultReasonLang, NULL, NULL);
    if(faultNode == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecSoap12AddFaultEntry",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
        xmlFree(faultReason);
        return(-1);
    }
    xmlFree(faultReason);

    if((faultSubCodeHref != NULL) && (faultSubCodeLocalPart != NULL)) {
        /* make sure that we have subcode (xkms) namespace declared */
        if(xmlNewNs(faultNode, faultSubCodeHref, BAD_CAST "xkms") == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlNewNs",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        "ns=%s",
                        xmlSecErrorsSafeString(faultSubCodeHref));
            return(-1);
        }
        if(xmlSecSoap12AddFaultSubcode(faultNode, faultSubCodeHref, faultSubCodeLocalPart) == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecSoap12AddFaultSubcode",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "href=%s,value=%s",
                        xmlSecErrorsSafeString(faultSubCodeHref),
                        xmlSecErrorsSafeString(faultSubCodeLocalPart));
            return(-1);
        }
    }

    return(0);
}

#endif /* XMLSEC_NO_SOAP */


/**
 * xmlSecXkmsServerCtxSetResult:
 * @ctx:         the pointer to XKMS processing context.
 * @resultMajor: the major result code.
 * @resultMinor: the minor result code.
 *
 * Sets the major/minor result code in the context if no other result is already
 * reported.
 */
void
xmlSecXkmsServerCtxSetResult(xmlSecXkmsServerCtxPtr ctx, xmlSecXkmsResultMajor resultMajor,
                             xmlSecXkmsResultMinor resultMinor) {
    xmlSecAssert(ctx != NULL);

    if((ctx->resultMajor == xmlSecXkmsResultMajorSuccess) &&
       (resultMinor != xmlSecXkmsResultMajorSuccess)) {
        ctx->resultMajor = resultMajor;
        ctx->resultMinor = resultMinor;
    } else if((ctx->resultMajor == xmlSecXkmsResultMajorSuccess) &&
       (ctx->resultMinor == xmlSecXkmsResultMinorNone)) {
        xmlSecAssert(resultMajor == xmlSecXkmsResultMajorSuccess);

        ctx->resultMinor = resultMinor;
    }
}


/**
 * xmlSecXkmsServerCtxDebugDump:
 * @ctx:        the pointer to XKMS processing context.
 * @output:     the pointer to output FILE.
 *
 * Prints the debug information about @ctx to @output.
 */
void
xmlSecXkmsServerCtxDebugDump(xmlSecXkmsServerCtxPtr ctx, FILE* output) {
    xmlSecAssert(ctx != NULL);
    xmlSecAssert(output != NULL);

    fprintf(output, "= XKMS SERVER CONTEXT: %s\n",
            (ctx->requestId != xmlSecXkmsServerRequestIdUnknown &&
             xmlSecXkmsServerRequestKlassGetName(ctx->requestId)) ?
                xmlSecXkmsServerRequestKlassGetName(ctx->requestId) :
                BAD_CAST "NULL");

    xmlSecQName2IntegerDebugDump(gXmlSecXkmsResultMajorInfo,
                ctx->resultMajor, BAD_CAST "resultMajor", output);
    xmlSecQName2IntegerDebugDump(gXmlSecXkmsMinorErrorInfo,
                ctx->resultMinor, BAD_CAST "resultMinor", output);

    fprintf(output, "== id: %s\n",
                (ctx->id) ? ctx->id : BAD_CAST "");
    fprintf(output, "== service: %s\n",
                (ctx->service) ? ctx->service : BAD_CAST "");
    fprintf(output, "== nonce: %s\n",
                (ctx->nonce) ? ctx->nonce : BAD_CAST "");
    fprintf(output, "== originalRequestId: %s\n",
                (ctx->originalRequestId) ? ctx->originalRequestId : BAD_CAST "");
    fprintf(output, "== pendingNotificationMechanism: %s\n",
                (ctx->pendingNotificationMechanism) ?
                    ctx->pendingNotificationMechanism :
                    BAD_CAST "");
    fprintf(output, "== pendingNotificationIdentifier: %s\n",
                (ctx->pendingNotificationIdentifier) ?
                    ctx->pendingNotificationIdentifier :
                    BAD_CAST "");
    if(ctx->responseLimit != XMLSEC_XKMS_NO_RESPONSE_LIMIT) {
        fprintf(output, "== ResponseLimit: %d\n", ctx->responseLimit);
    }
    xmlSecQName2BitMaskDebugDump(gXmlSecXkmsResponseMechanismInfo,
                ctx->responseMechanismMask, BAD_CAST "responseMechanism", output);

    if(ctx->expectedService != NULL) {
        fprintf(output, "== expected service: %s\n", ctx->expectedService);
    }
    fprintf(output, "== flags: 0x%08x\n", ctx->flags);
    fprintf(output, "== flags2: 0x%08x\n", ctx->flags2);

    fprintf(output, "== Key Info Read Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(ctx->keyInfoReadCtx), output);

    fprintf(output, "== Key Info Write Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(ctx->keyInfoWriteCtx), output);

    if(xmlSecPtrListGetSize(&(ctx->enabledRespondWithIds)) > 0) {
        fprintf(output, "== Enabled RespondWith: ");
        xmlSecTransformIdListDebugDump(&(ctx->enabledRespondWithIds), output);
    } else {
        fprintf(output, "== Enabled RespondWith: all\n");
    }

    if(xmlSecPtrListGetSize(&(ctx->enabledServerRequestIds)) > 0) {
        fprintf(output, "== Enabled ServerRequest: ");
        xmlSecTransformIdListDebugDump(&(ctx->enabledServerRequestIds), output);
    } else {
        fprintf(output, "== Enabled ServerRequest: all\n");
    }

    fprintf(output, "== RespondWith List:\n");
    xmlSecPtrListDebugDump(&(ctx->respWithList), output);

    fprintf(output, "== Keys:\n");
    xmlSecPtrListDebugDump(&(ctx->keys), output);

    if(ctx->compoundRequestContexts != NULL) {
        fprintf(output, "== Compound Request:\n");
        xmlSecPtrListDebugDump(ctx->compoundRequestContexts, output);
    }
}

/**
 * xmlSecXkmsServerCtxDebugXmlDump:
 * @ctx:        the pointer to XKMS processing context.
 * @output:     the pointer to output FILE.
 *
 * Prints the debug information about @ctx to @output in XML format.
 */
void
xmlSecXkmsServerCtxDebugXmlDump(xmlSecXkmsServerCtxPtr ctx, FILE* output) {
    xmlSecAssert(ctx != NULL);
    xmlSecAssert(output != NULL);

    fprintf(output, "<XkmsServerRequestContext name=\"");
    xmlSecPrintXmlString(output,
            (ctx->requestId != xmlSecXkmsServerRequestIdUnknown) ?
                xmlSecXkmsServerRequestKlassGetName(ctx->requestId) :
                BAD_CAST "NULL"
    );
    fprintf(output, "\">\n");

    xmlSecQName2IntegerDebugXmlDump(gXmlSecXkmsResultMajorInfo,
                ctx->resultMajor, BAD_CAST "MajorError", output);
    xmlSecQName2IntegerDebugXmlDump(gXmlSecXkmsMinorErrorInfo,
                ctx->resultMinor, BAD_CAST "MinorError", output);

    fprintf(output, "<Id>");
    xmlSecPrintXmlString(output, ctx->id);
    fprintf(output, "</Id>\n");

    fprintf(output, "<Service>");
    xmlSecPrintXmlString(output, ctx->service);
    fprintf(output, "</Service>\n");

    fprintf(output, "<Nonce>");
    xmlSecPrintXmlString(output, ctx->nonce);
    fprintf(output, "</Nonce>\n");

    fprintf(output, "<OriginalRequestId>");
    xmlSecPrintXmlString(output, ctx->originalRequestId);
    fprintf(output, "</OriginalRequestId>\n");

    fprintf(output, "<PendingNotificationMechanism>");
    xmlSecPrintXmlString(output, ctx->pendingNotificationMechanism);
    fprintf(output, "</PendingNotificationMechanism>\n");

    fprintf(output, "<PendingNotificationIdentifier>");
    xmlSecPrintXmlString(output, ctx->pendingNotificationIdentifier);
    fprintf(output, "</PendingNotificationIdentifier>\n");

    if(ctx->responseLimit != XMLSEC_XKMS_NO_RESPONSE_LIMIT) {
        fprintf(output, "<ResponseLimit>%d</ResponseLimit>\n", ctx->responseLimit);
    }
    xmlSecQName2BitMaskDebugXmlDump(gXmlSecXkmsResponseMechanismInfo,
                ctx->responseMechanismMask, BAD_CAST "ResponseMechanism", output);


    fprintf(output, "<ExpectedService>");
    xmlSecPrintXmlString(output, ctx->expectedService);
    fprintf(output, "</ExpectedService>\n");

    fprintf(output, "<Flags>%08x</Flags>\n", ctx->flags);
    fprintf(output, "<Flags2>%08x</Flags2>\n", ctx->flags2);

    fprintf(output, "<KeyInfoReadCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(ctx->keyInfoReadCtx), output);
    fprintf(output, "</KeyInfoReadCtx>\n");

    fprintf(output, "<KeyInfoWriteCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(ctx->keyInfoWriteCtx), output);
    fprintf(output, "</KeyInfoWriteCtx>\n");

    if(xmlSecPtrListGetSize(&(ctx->enabledRespondWithIds)) > 0) {
        fprintf(output, "<EnabledRespondWith>\n");
        xmlSecTransformIdListDebugXmlDump(&(ctx->enabledRespondWithIds), output);
        fprintf(output, "</EnabledRespondWith>\n");
    } else {
        fprintf(output, "<EnabledRespondWith>all</EnabledRespondWith>\n");
    }

    if(xmlSecPtrListGetSize(&(ctx->enabledServerRequestIds)) > 0) {
        fprintf(output, "<EnabledServerRequest>\n");
        xmlSecTransformIdListDebugXmlDump(&(ctx->enabledServerRequestIds), output);
        fprintf(output, "</EnabledServerRequest>\n");
    } else {
        fprintf(output, "<EnabledServerRequest>all</EnabledServerRequest>\n");
    }


    fprintf(output, "<RespondWithList>\n");
    xmlSecPtrListDebugXmlDump(&(ctx->respWithList), output);
    fprintf(output, "</RespondWithList>\n");

    fprintf(output, "<Keys>\n");
    xmlSecPtrListDebugXmlDump(&(ctx->keys), output);
    fprintf(output, "</Keys>\n");

    if(ctx->compoundRequestContexts != NULL) {
        fprintf(output, "<CompoundRequest>\n");
        xmlSecPtrListDebugXmlDump(ctx->compoundRequestContexts, output);
        fprintf(output, "</CompoundRequest>\n");
    }

    fprintf(output, "</XkmsServerRequestContext>\n");
}

/**
 *  <xkms:MessageAbstractType Id Service Nonce?>
 *      <ds:Signature>?
 *      <xkms:MessageExtension>*
 *      (<xkms:OpaqueClientData>
 *          <xkms:OpaqueData>?
 *      )?
 *
 *  <xkms:RequestAbstractType Id Service Nonce? OriginalRequestId? ResponseLimit?>
 *      <ds:Signature>?
 *      <xkms:MessageExtension>*
 *      (<xkms:OpaqueClientData>
 *          <xkms:OpaqueData>?
 *      )?
 *      <xkms:ResponseMechanism>*
 *      <xkms:RespondWith>*
 *      <xkms:PendingNotification Mechanism Identifier>?
 *
 * XML Schema:
 *
 *   <!-- RequestAbstractType -->
 *   <complexType name="RequestAbstractType" abstract="true">
 *      <complexContent>
 *         <extension base="xkms:MessageAbstractType">
 *            <sequence>
 *              <element ref="xkms:ResponseMechanism" minOccurs="0"
 *                     maxOccurs="unbounded"/>
 *               <element ref="xkms:RespondWith" minOccurs="0"
 *                     maxOccurs="unbounded"/>
 *               <element ref="xkms:PendingNotification" minOccurs="0"/>
 *            </sequence>
 *            <attribute name="OriginalRequestId" type="anyURI"
 *                  use="optional"/>
 *            <attribute name="ResponseLimit" type="integer" use="optional"/>
 *         </extension>
 *      </complexContent>
 *   </complexType>
 *   <!-- /RequestAbstractType -->
 *
 *   <!-- MessageAbstractType -->
 *   <complexType name="MessageAbstractType" abstract="true">
 *      <sequence>
 *         <element ref="ds:Signature" minOccurs="0"/>
 *         <element ref="xkms:MessageExtension" minOccurs="0"
 *               maxOccurs="unbounded"/>
 *         <element ref="xkms:OpaqueClientData" minOccurs="0"/>
 *      </sequence>
 *      <attribute name="Id" type="ID" use="required"/>
 *      <attribute name="Service" type="anyURI" use="required"/>
 *      <attribute name="Nonce" type="base64Binary" use="optional"/>
 *   </complexType>
 *   <!-- /MessageAbstractType -->
 */
static int
xmlSecXkmsServerCtxRequestAbstractTypeNodeRead(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr* node) {
    xmlNodePtr cur;
    xmlChar* tmp;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2((*node) != NULL, -1);

    cur = (*node);
    xmlSecAssert2(cur != NULL, -1);

    /* required Id attribute */
    xmlSecAssert2(ctx->id == NULL, -1);
    ctx->id = xmlGetProp(cur, xmlSecAttrId);
    if(ctx->id == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlGetProp",
                    XMLSEC_ERRORS_R_XML_FAILED,
                    "name=%s;node=%s",
                    xmlSecErrorsSafeString(xmlSecAttrId),
                    xmlSecErrorsSafeString(cur->name));
        return(-1);
    }

    /* required Service attribute */
    xmlSecAssert2(ctx->service == NULL, -1);
    ctx->service = xmlGetProp(cur, xmlSecAttrService);
    if(ctx->service == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlGetProp",
                    XMLSEC_ERRORS_R_XML_FAILED,
                    "name=%s;node=%s",
                    xmlSecErrorsSafeString(xmlSecAttrService),
                    xmlSecErrorsSafeString(cur->name));
        return(-1);
    }

    /* check service */
    if((ctx->expectedService != NULL) && (!xmlStrEqual(ctx->expectedService, ctx->service))) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_DATA,
                    "expectedService=%s;actualService=%s",
                    xmlSecErrorsSafeString(ctx->expectedService),
                    xmlSecErrorsSafeString(ctx->service));
        return(-1);
    }

    /* optional Nonce attribute */
    xmlSecAssert2(ctx->nonce == NULL, -1);
    ctx->nonce = xmlGetProp(cur, xmlSecAttrNonce);

    /* optional OriginalRequestId attribute */
    xmlSecAssert2(ctx->originalRequestId == NULL, -1);
    ctx->originalRequestId = xmlGetProp(cur, xmlSecAttrOriginalRequestId);

    /* optional ResponseLimit attribute */
    xmlSecAssert2(ctx->responseLimit == XMLSEC_XKMS_NO_RESPONSE_LIMIT, -1);
    tmp = xmlGetProp(cur, xmlSecAttrResponseLimit);
    if(tmp != NULL) {
        ctx->responseLimit = atoi((char*)tmp);
        xmlFree(tmp);
    }

    /* now read children */
    cur = xmlSecGetNextElementNode(cur->children);

    /* first node is optional <dsig:Signature/> node */
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeSignature, xmlSecDSigNs)) {
        ret = xmlSecXkmsServerCtxSignatureNodeRead(ctx, cur);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecXkmsServerCtxSignatureNodeRead",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next is zero or more <xkms:MessageExtension/> nodes */
    ret = xmlSecXkmsServerCtxMessageExtensionNodesRead(ctx, &cur);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxMessageExtensionNodesRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* next is optional <xkms:OpaqueClientData/> node */
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeOpaqueClientData, xmlSecXkmsNs)) {
        ret = xmlSecXkmsServerCtxOpaqueClientDataNodeRead(ctx, cur);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecXkmsServerCtxOpaqueClientDataNodeRead",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next is zero or more <xkms:ResponseMechanism/> nodes */
    ret = xmlSecQName2BitMaskNodesRead(gXmlSecXkmsResponseMechanismInfo, &cur,
                        xmlSecNodeResponseMechanism, xmlSecXkmsNs,
                        ((ctx->flags & XMLSEC_XKMS_SERVER_FLAGS_STOP_ON_UNKNOWN_RESPONSE_MECHANISM) != 0) ? 1 : 0,
                        &ctx->responseMechanismMask);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecQName2BitMaskNodesRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecNodeResponseMechanism));
        return(-1);
    }

    /* next is zero or more <xkms:RespondWith/> nodes */
    ret = xmlSecXkmsServerCtxRespondWithNodesRead(ctx, &cur);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxRespondWithNodesRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* next is optional <xkms:PendingNotification/> node */
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodePendingNotification, xmlSecXkmsNs)) {
        ret = xmlSecXkmsServerCtxPendingNotificationNodeRead(ctx, cur);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecXkmsServerCtxPendingNotificationNodeRead",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    (*node) = cur;
    return(0);
}

static int
xmlSecXkmsServerCtxSignatureNodeRead(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* todo: verify signature and make sure that correct data was signed */
    return(0);
}

/**
 *   <!-- MessageExtension -->
 *   <element name="MessageExtension" type="xkms:MessageExtensionAbstractType"
 *         abstract="true"/>
 *   <complexType name="MessageExtensionAbstractType" abstract="true"/>
 *   <!-- /MessageExtension -->
 */
static int
xmlSecXkmsServerCtxMessageExtensionNodesRead(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr* node) {
    xmlNodePtr cur;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->firtsMsgExtNode == NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = (*node);
    while((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeMessageExtension, xmlSecXkmsNs)) {
        if(ctx->firtsMsgExtNode == NULL) {
            ctx->firtsMsgExtNode = cur;
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    (*node) = cur;
    return(0);
}

static int
xmlSecXkmsServerCtxOpaqueClientDataNodeRead(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->opaqueClientDataNode == NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* remember that node, will copy it in the response later */
    ctx->opaqueClientDataNode = node;
    return(0);
}

static int
xmlSecXkmsServerCtxRespondWithNodesRead(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr* node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = (*node);
    while((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeRespondWith, xmlSecXkmsNs)) {
        xmlSecXkmsRespondWithId id = xmlSecXkmsRespondWithIdUnknown;

        if(xmlSecPtrListGetSize(&(ctx->enabledRespondWithIds)) > 0) {
            id = xmlSecXkmsRespondWithIdListFindByNodeValue(&(ctx->enabledRespondWithIds), cur);
        } else {
            id = xmlSecXkmsRespondWithIdListFindByNodeValue(xmlSecXkmsRespondWithIdsGet(), cur);
        }

        if(id != xmlSecXkmsRespondWithIdUnknown) {
            ret = xmlSecXkmsRespondWithNodeRead(id, ctx, cur);
            if(ret < 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "xmlSecCreateTree",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
        } else if((ctx->flags & XMLSEC_XKMS_SERVER_FLAGS_STOP_ON_UNKNOWN_RESPOND_WITH) != 0) {
            xmlChar* content ;

            content = xmlNodeGetContent(cur);
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        NULL,
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "name=%s,value=%s",
                        xmlSecErrorsSafeString(cur->name),
                        xmlSecErrorsSafeString(content));
            if(content != NULL) {
                xmlFree(content);
            }
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    (*node) = cur;
    return(0);
}

/**
 * XML Schema:
 *   <!-- PendingNotification -->
 *   <element name="PendingNotification" type="xkms:PendingNotificationType"/>
 *   <complexType name="PendingNotificationType">
 *      <attribute name="Mechanism" type="anyURI" use="required"/>
 *      <attribute name="Identifier" type="anyURI" use="required"/>
 *   </complexType>
 *   <!-- /PendingNotification -->
 */
static int
xmlSecXkmsServerCtxPendingNotificationNodeRead(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    xmlSecAssert2(ctx->pendingNotificationMechanism == NULL, -1);
    ctx->pendingNotificationMechanism = xmlGetProp(node, xmlSecAttrMechanism);
    if(ctx->pendingNotificationMechanism == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlGetProp",
                    XMLSEC_ERRORS_R_XML_FAILED,
                    "name=%s;node=%s",
                    xmlSecErrorsSafeString(xmlSecAttrMechanism),
                    xmlSecErrorsSafeString(node->name));
        return(-1);
    }

    xmlSecAssert2(ctx->pendingNotificationIdentifier == NULL, -1);
    ctx->pendingNotificationIdentifier = xmlGetProp(node, xmlSecAttrIdentifier);
    if(ctx->pendingNotificationIdentifier == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlGetProp",
                    XMLSEC_ERRORS_R_XML_FAILED,
                    "name=%s;node=%s",
                    xmlSecErrorsSafeString(xmlSecAttrIdentifier),
                    xmlSecErrorsSafeString(node->name));
        return(-1);
    }

    return(0);
}

/**
 *  <xkms:PendingRequestType Id Service Nonce? OriginalRequestId? ResponseLimit? ResponseId?>
 *      <ds:Signature>?
 *      <xkms:MessageExtension>*
 *      (<xkms:OpaqueClientData>
 *          <xkms:OpaqueData>?
 *      )?
 *      <xkms:ResponseMechanism>*
 *      <xkms:RespondWith>*
 *      <xkms:PendingNotification Mechanism Identifier>?
 *
 * XML Schema:
 *
 *   <!-- PendingRequest -->
 *   <element name="PendingRequest" type="xkms:PendingRequestType"/>
 *   <complexType name="PendingRequestType">
 *       <complexContent>
 *           <extension base="xkms:RequestAbstractType">
 *               <attribute name="ResponseId" type="anyURI" use="optional"/>
 *            </extension>
 *       </complexContent>
 *    </complexType>
 *    <!-- /PendingRequest --> *
 */
static int
xmlSecXkmsServerCtxPendingRequestNodeRead(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr* node) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first read "parent" type */
    ret = xmlSecXkmsServerCtxRequestAbstractTypeNodeRead(ctx, node);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxRequestAbstractTypeNodeRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* todo: read responseId */
    return(0);
}

/**
 *  <xkms:QueryKeyBinding Id?
 *      <ds:KeyInfo>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:UseKeyWith Application Identifier>*
 *      <xkms:TimeInstant Time>?
 *
 * XML Schema:
 *   <!-- QueryKeyBinding -->
 *   <element name="QueryKeyBinding" type="xkms:QueryKeyBindingType"/>
 *   <complexType name="QueryKeyBindingType">
 *      <complexContent>
 *          <extension base="xkms:KeyBindingAbstractType">
 *              <sequence>
 *                  <element ref="xkms:TimeInstant" minOccurs="0"/>
 *              </sequence>
 *          </extension>
 *      </complexContent>
 *   </complexType>
 *   <!-- /QueryKeyBinding -->
 */
static int
xmlSecXkmsServerCtxQueryKeyBindingNodeRead(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first read "parent" type */
    cur = node;
    ret = xmlSecXkmsServerCtxKeyBindingAbstractTypeNodeRead(ctx, &cur);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxKeyBindingAbstractTypeNodeRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* next is optional <xkms:TimeInstant/> node */
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeTimeInstant, xmlSecXkmsNs)) {
        ret = xmlSecXkmsServerCtxTimeInstantNodeRead(ctx, cur);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecXkmsServerCtxTimeInstantNodeRead",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* check that there is nothing after the last node */
    if(cur != NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
                    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

/**
 *  <xkms:KeyBindingAbstractType Id?>
 *      <ds:KeyInfo>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:UseKeyWith Application Identifier>*
 *
 * XML Schema:
 *    <!-- KeyBindingAbstractType-->
 *    <complexType name="KeyBindingAbstractType" abstract="true">
 *       <sequence>
 *          <element ref="ds:KeyInfo" minOccurs="0"/>
 *          <element ref="xkms:KeyUsage" minOccurs="0" maxOccurs="3"/>
 *          <element ref="xkms:UseKeyWith" minOccurs="0"
 *                   maxOccurs="unbounded"/>
 *       </sequence>
 *       <attribute name="Id" type="ID" use="optional"/>
 *    </complexType>
 *    <!-- /KeyBindingAbstractType-->
 */
static int
xmlSecXkmsServerCtxKeyBindingAbstractTypeNodeRead(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr* node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2((*node) != NULL, -1);

    cur = (*node);
    xmlSecAssert2(cur != NULL, -1);

    /* we don't care about Id attribute in this node */
    cur = xmlSecGetNextElementNode(cur->children);

    /* first node is optional <dsig:KeyInfo/> node. for now we only remember pointer */
    xmlSecAssert2(ctx->keyInfoNode == NULL, -1);
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeKeyInfo, xmlSecDSigNs)) {
        ctx->keyInfoNode = cur;
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next is zero or more <xkms:KeyUsage/> nodes */
    ret = xmlSecQName2BitMaskNodesRead(gXmlSecXkmsKeyUsageInfo, &cur,
                    xmlSecNodeKeyUsage, xmlSecXkmsNs,
                    ((ctx->flags & XMLSEC_XKMS_SERVER_FLAGS_STOP_ON_UNKNOWN_KEY_USAGE) != 0) ? 1 : 0,
                    &(ctx->keyInfoReadCtx.keyReq.keyUsage));
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecQName2BitMaskNodesRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecNodeKeyUsage));
        return(-1);
    }

    /* next is zero or more <xkms:UseKeyWith/> nodes */
    ret = xmlSecXkmsServerCtxUseKeyWithNodesRead(ctx, &cur);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxUseKeyWithNodesRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    (*node) = cur;
    return(0);
}

static int
xmlSecXkmsServerCtxKeyBindingAbstractTypeNodeWrite(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node, xmlSecKeyPtr key) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    /* generate and add Id attribute */
    ret = xmlSecGenerateAndAddID(node, xmlSecAttrId, ctx->idPrefix, ctx->idLen);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGenerateAndAddID",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* <dsig:KeyInfo/> node */
    cur = xmlSecAddChild(node, xmlSecNodeKeyInfo, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecAddChild",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "node=%s",
                    xmlSecErrorsSafeString(xmlSecNodeKeyInfo));
        return(-1);
    }

    ret = xmlSecXkmsServerCtxKeyInfoNodeWrite(ctx, cur, key);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxKeyInfoNodeWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* next is <xkms:KeyUsage/> node */
    ret = xmlSecQName2BitMaskNodesWrite(gXmlSecXkmsKeyUsageInfo, node,
                    xmlSecNodeKeyUsage, xmlSecXkmsNs,
                    key->usage);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecQName2BitMaskNodesWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecNodeKeyUsage));
        return(-1);
    }

    /* and the last node is <xkms:UseKeyWith/> */
    ret = xmlSecXkmsServerCtxUseKeyWithNodesWrite(ctx, node, key);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxUseKeyWithNodesWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

static int
xmlSecXkmsServerCtxKeyInfoNodeWrite(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node, xmlSecKeyPtr key) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* add child nodes as requested in <xkms:RespondWith/> nodes */
    ret = xmlSecXkmsRespondWithIdListWrite(&(ctx->respWithList), ctx, node);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsRespondWithIdListWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    ret = xmlSecKeyInfoNodeWrite(node, key, &(ctx->keyInfoWriteCtx));
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecKeyInfoNodeWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}


/**
 * XML Schema:
 *    <!-- UseKeyWith -->
 *    <element name="UseKeyWith" type="xkms:UseKeyWithType"/>
 *    <complexType name="UseKeyWithType">
 *      <attribute name="Application" type="anyURI" use="required"/>
 *      <attribute name="Identifier" type="string" use="required"/>
 *    </complexType>
 *    <!-- /UseKeyWith -->
 */
static int
xmlSecXkmsServerCtxUseKeyWithNodesRead(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr* node) {
    xmlSecPtrListPtr list;
    xmlNodePtr cur;
    xmlSecKeyUseWithPtr keyUseWith;
    xmlChar* application;
    xmlChar* identifier;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    list = &(ctx->keyInfoReadCtx.keyReq.keyUseWithList);
    xmlSecAssert2(xmlSecPtrListGetSize(list) == 0, -1);

    cur = (*node);
    while((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeUseKeyWith, xmlSecXkmsNs)) {
        application = xmlGetProp(cur, xmlSecAttrApplication);
        if(application == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlGetProp",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        "name=%s;node=%s",
                        xmlSecErrorsSafeString(xmlSecAttrApplication),
                        xmlSecErrorsSafeString(cur->name));
            return(-1);
        }

        identifier = xmlGetProp(cur, xmlSecAttrIdentifier);
        if(identifier == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlGetProp",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        "name=%s;node=%s",
                        xmlSecErrorsSafeString(xmlSecAttrIdentifier),
                        xmlSecErrorsSafeString(cur->name));
            xmlFree(application);
            return(-1);
        }

        keyUseWith = xmlSecKeyUseWithCreate(application, identifier);
        if(keyUseWith == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecKeyUseWithCreate",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlFree(application);
            xmlFree(identifier);
            return(-1);
        }
        xmlFree(application);
        xmlFree(identifier);

        ret = xmlSecPtrListAdd(list, keyUseWith);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecPtrListAdd",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecKeyUseWithDestroy(keyUseWith);
            return(-1);
        }

        cur = xmlSecGetNextElementNode(cur->next);
    }

    (*node) = cur;
    return(0);
}

static int
xmlSecXkmsServerCtxUseKeyWithNodesWrite(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node, xmlSecKeyPtr key) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    /* todo: write UseKeyWith */
    return(0);
}


static int
xmlSecXkmsServerCtxTimeInstantNodeRead(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* todo: parse xml schema dataTime or use libxml? */
    return(0);
}

/**
 *  <xkms:ResultType Id Service Nonce? ResultMajor ResultMinor? RequestId?>
 *      <ds:Signature>?
 *      <xkms:MessageExtension>*
 *      (<xkms:OpaqueClientData>
 *          <xkms:OpaqueData>?
 *      )?
 *      <xkms:RequestSignatureValue>*
 *
 * XML Schema:
 *    <!-- ResultType -->
 *    <element name="Result" type="xkms:ResultType"/>
 *    <complexType name="ResultType">
 *       <complexContent>
 *          <extension base="xkms:MessageAbstractType">
 *             <sequence>
 *                <element ref="xkms:RequestSignatureValue" minOccurs="0"/>
 *             </sequence>
 *             <attribute name="ResultMajor" type="QName" use="required"/>
 *             <attribute name="ResultMinor" type="QName" use="optional"/>
 *             <attribute name="RequestId" type="anyURI" use="optional"/>
 *          </extension>
 *       </complexContent>
 *    </complexType>
 *    <!-- /ResultType -->
 */
static int
xmlSecXkmsServerCtxResultTypeNodeWrite(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* generate and add Id attribute */
    ret = xmlSecGenerateAndAddID(node, xmlSecAttrId, ctx->idPrefix, ctx->idLen);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGenerateAndAddID",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* todo: generate nonce? */

    /* set Service atribute (required) */
    if((ctx->service == NULL) || (xmlSetProp(node, xmlSecAttrService, ctx->service) == NULL)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSetProp",
                    XMLSEC_ERRORS_R_XML_FAILED,
                    "name=%s,value=%s",
                    xmlSecErrorsSafeString(xmlSecAttrService),
                    xmlSecErrorsSafeString(ctx->service));
        return(-1);
    }


    /* set RequestId atribute (optional) */
    if((ctx->id != NULL) && (xmlSetProp(node, xmlSecAttrRequestId, ctx->id) == NULL)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSetProp",
                    XMLSEC_ERRORS_R_XML_FAILED,
                    "name=%s,value=%s",
                    xmlSecErrorsSafeString(xmlSecAttrRequestId),
                    xmlSecErrorsSafeString(ctx->id));
        return(-1);
    }


    /* set major code (required) */
    ret = xmlSecQName2IntegerAttributeWrite(gXmlSecXkmsResultMajorInfo, node,
                                             xmlSecAttrResultMajor, ctx->resultMajor);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecQName2IntegerAttributeWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s,value=%d",
                    xmlSecErrorsSafeString(xmlSecAttrResultMajor),
                    ctx->resultMajor);
        return(-1);
    }

    /* set minor code (optional) */
    if(ctx->resultMinor != xmlSecXkmsResultMinorNone) {
        ret = xmlSecQName2IntegerAttributeWrite(gXmlSecXkmsMinorErrorInfo, node,
                                             xmlSecAttrResultMinor, ctx->resultMinor);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecQName2IntegerAttributeWrite",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "name=%s,value=%d",
                        xmlSecErrorsSafeString(xmlSecAttrResultMinor),
                        ctx->resultMinor);
            return(-1);
        }
    }

    /* todo: create signature template */

    /* todo: create message extension nodes? */

    /* <xkms:OpaqueClientData/>: An XKMS service SHOULD return the value of
     * the <OpaqueClientData> element unmodified in a request in a response
     * with status code Succes */
    if((ctx->resultMajor == xmlSecXkmsResultMajorSuccess) && (ctx->opaqueClientDataNode != NULL)) {
        xmlNodePtr copyNode;

        copyNode = xmlDocCopyNode(ctx->opaqueClientDataNode, node->doc, 1);
        if(copyNode == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSetProp",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        "name=%s",
                        xmlSecErrorsSafeString(ctx->opaqueClientDataNode->name));
            return(-1);
        }

        if(xmlSecAddChildNode(node, copyNode) == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecAddChildNode",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "name=%s",
                        xmlSecErrorsSafeString(copyNode->name));
            return(-1);
        }
    }

    ret = xmlSecXkmsServerCtxRequestSignatureValueNodeWrite(ctx, node);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxRequestSignatureValueNodeWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

/**
 * A service SHOULD include the <RequestSignatureValue> element in a response
 * if the following conditions are satisfied and MUST NOT include the value
 * otherwise:
 *
 *
 *  - The <ds:Signature> element was present in the corresponding request
 *  - The service successfully verified the <ds:Signature> element in the
 *  corresponding request, and
 *  - The ResponseMechanism RequestSignatureValue was specified.
 *
 */
static int
xmlSecXkmsServerCtxRequestSignatureValueNodeWrite(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* todo: check all conditions for RequestSignatureValue */
    if((ctx->responseMechanismMask & XMLSEC_XKMS_RESPONSE_MECHANISM_MASK_REQUEST_SIGNATURE_VALUE) == 0) {
        /* The ResponseMechanism RequestSignatureValue was not specified. */
        return(0);
    }

    /* todo: write RequestSignatureValue */
    return(0);
}


/**
 *
 *  <xkms:UnverifiedKeyBindingType Id?>
 *      <ds:KeyInfo>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:UseKeyWith Application Identifier>*
 *      <xkms:ValidityInterval NotBefore NotOnOrAfter>?
 *
 * XML Schema:
 *
 *    <!-- UnverifiedKeyBinding -->
 *    <element name="UnverifiedKeyBinding" type="xkms:UnverifiedKeyBindingType"/>
 *    <complexType name="UnverifiedKeyBindingType">
 *       <complexContent>
 *          <extension base="xkms:KeyBindingAbstractType">
 *             <sequence>
 *                 <element ref="xkms:ValidityInterval" minOccurs="0"/>
 *             </sequence>
 *          </extension>
 *       </complexContent>
 *    </complexType>
 *    <!-- /UnverifiedKeyBinding -->
 */
static int
xmlSecXkmsServerCtxUnverifiedKeyBindingNodeWrite(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node, xmlSecKeyPtr key) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first write "parent" type */
    ret = xmlSecXkmsServerCtxKeyBindingAbstractTypeNodeWrite(ctx, node, key);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxKeyBindingAbstractTypeNodeWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* <xkms:ValidityInterval/> node */
    ret = xmlSecXkmsServerCtxValidityIntervalNodeWrite(ctx, node, key);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxValidityIntervalNodeWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

static int
xmlSecXkmsServerCtxValidityIntervalNodeWrite(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node, xmlSecKeyPtr key) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* todo: write key validity interval */
    return(0);
}

/**
 *  <xkms:KeyBinding Id?>
 *      <ds:KeyInfo>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:UseKeyWith Application Identifier>*
 *      <xkms:ValidityInterval NotBefore NotOnOrAfter>?
 *      <xkms:Status StatusValue>
 *          (<xkms:ValidReason>?
 *           <xkms:IndeterminateReason>?
 *           <xkms:InvalidReason>?
 *           )*
 *
 * XML Schema:
 *
 *    <!-- KeyBinding -->
 *    <element name="KeyBinding" type="xkms:KeyBindingType"/>
 *    <complexType name="KeyBindingType">
 *        <complexContent>
 *            <extension base="xkms:UnverifiedKeyBindingType">
 *                <sequence>
 *                    <element ref="xkms:Status"/>
 *                </sequence>
 *            </extension>
 *        </complexContent>
 *    </complexType>
 *    <!-- /KeyBinding -->
 */
static int
xmlSecXkmsServerCtxKeyBindingNodeWrite(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node, xmlSecKeyPtr key) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first write "parent" type */
    ret = xmlSecXkmsServerCtxUnverifiedKeyBindingNodeWrite(ctx, node, key);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxKeyBindingAbstractTypeNodeWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* <xkms:Status/> node */
    ret = xmlSecXkmsServerCtxKeyBindingStatusNodeWrite(ctx, node, key);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxKeyBindingStatusNodeWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

/**
 *  <xkms:Status StatusValue>
 *      (<xkms:ValidReason>?
 *       <xkms:IndeterminateReason>?
 *       <xkms:InvalidReason>?
 *      )*
 *
 * XML Schema:
 *
 *    <!-- Status -->
 *    <element name="Status" type="xkms:StatusType"/>
 *    <complexType name="StatusType">
 *       <sequence>
 *          <element ref="xkms:ValidReason" minOccurs="0"
 *                maxOccurs="unbounded"/>
 *          <element ref="xkms:IndeterminateReason" minOccurs="0"
 *                maxOccurs="unbounded"/>
 *          <element ref="xkms:InvalidReason" minOccurs="0"
 *                maxOccurs="unbounded"/>
 *       </sequence>
 *       <attribute name="StatusValue" type="xkms:KeyBindingStatus"
 *             use="required"/>
 *    </complexType>
 *    <simpleType name="KeyBindingStatus">
 *       <restriction base="QName">
 *          <enumeration value="xkms:Valid"/>
 *          <enumeration value="xkms:Invalid"/>
 *          <enumeration value="xkms:Indeterminate"/>
 *       </restriction>
 *    </simpleType>
 *    <!-- /Status -->
 */
static int
xmlSecXkmsServerCtxKeyBindingStatusNodeWrite(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node, xmlSecKeyPtr key) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = xmlSecAddChild(node, xmlSecNodeStatus, xmlSecXkmsNs);
    if(cur == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecAddChild",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "node=%s",
                    xmlSecErrorsSafeString(xmlSecNodeStatus));
        return(-1);
    }

    /* if we are here then the key was validated */
    ret = xmlSecQName2IntegerAttributeWrite(gXmlSecXkmsKeyBindingStatusInfo, cur,
                    xmlSecAttrStatusValue, xmlSecXkmsKeyBindingStatusValid);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecQName2IntegerAttributeWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecAttrStatusValue));
        return(-1);
    }

    /* todo: write the reasons */
    return(0);
}

/************************************************************************
 *
 * xmlSecXkmsServerCtx list
 *
 ************************************************************************/
static xmlSecPtrListKlass xmlSecXkmsServerCtxPtrListKlass = {
    BAD_CAST "xkms-server-ctx-list",
    NULL,                                                               /* xmlSecPtrDuplicateItemMethod duplicateItem; */
    (xmlSecPtrDestroyItemMethod)xmlSecXkmsServerCtxDestroy,             /* xmlSecPtrDestroyItemMethod destroyItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecXkmsServerCtxDebugDump,         /* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecXkmsServerCtxDebugXmlDump,      /* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

xmlSecPtrListId
xmlSecXkmsServerCtxPtrListGetKlass(void) {
    return(&xmlSecXkmsServerCtxPtrListKlass);
}


/**************************************************************************
 *
 * Global xmlSecXkmsRespondWithIds list functions
 *
 *************************************************************************/
static xmlSecPtrList xmlSecAllXkmsRespondWithIds;


/**
 * xmlSecXkmsRespondWithIdsGet:
 *
 * Gets global registered RespondWith klasses list.
 *
 * Returns: the pointer to list of all registered RespondWith klasses.
 */
xmlSecPtrListPtr
xmlSecXkmsRespondWithIdsGet(void) {
    return(&xmlSecAllXkmsRespondWithIds);
}

/**
 * xmlSecXkmsRespondWithIdsInit:
 *
 * Initializes the RespondWith klasses. This function is called from the
 * #xmlSecInit function and the application should not call it directly.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecXkmsRespondWithIdsInit(void) {
    int ret;

    ret = xmlSecPtrListInitialize(xmlSecXkmsRespondWithIdsGet(), xmlSecXkmsRespondWithIdListId);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecPtrListPtrInitialize",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "xmlSecXkmsRespondWithIdListId");
        return(-1);
    }

    ret = xmlSecXkmsRespondWithIdsRegisterDefault();
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsRespondWithIdsRegisterDefault",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecXkmsRespondWithIdsShutdown:
 *
 * Shuts down the keys data klasses. This function is called from the
 * #xmlSecShutdown function and the application should not call it directly.
 */
void
xmlSecXkmsRespondWithIdsShutdown(void) {
    xmlSecPtrListFinalize(xmlSecXkmsRespondWithIdsGet());
}

/**
 * xmlSecXkmsRespondWithIdsRegister:
 * @id:         the RespondWith klass.
 *
 * Registers @id in the global list of RespondWith klasses.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecXkmsRespondWithIdsRegister(xmlSecXkmsRespondWithId id) {
    int ret;

    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);

    ret = xmlSecPtrListAdd(xmlSecXkmsRespondWithIdsGet(), (xmlSecPtr)id);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecPtrListAdd",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "RespondWith=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecXkmsRespondWithIdsRegisterDefault:
 *
 * Registers default (implemented by XML Security Library)
 * RespondWith klasses: KeyName, KeyValue,...
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecXkmsRespondWithIdsRegisterDefault(void) {
    if(xmlSecXkmsRespondWithIdsRegister(xmlSecXkmsRespondWithKeyNameId) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsRespondWithIdsRegister",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(xmlSecXkmsRespondWithKeyNameId)));
        return(-1);
    }

    if(xmlSecXkmsRespondWithIdsRegister(xmlSecXkmsRespondWithKeyValueId) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsRespondWithIdsRegister",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(xmlSecXkmsRespondWithKeyValueId)));
        return(-1);
    }

    if(xmlSecXkmsRespondWithIdsRegister(xmlSecXkmsRespondWithPrivateKeyId) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsRespondWithIdsRegister",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(xmlSecXkmsRespondWithPrivateKeyId)));
        return(-1);
    }

    if(xmlSecXkmsRespondWithIdsRegister(xmlSecXkmsRespondWithRetrievalMethodId) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsRespondWithIdsRegister",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(xmlSecXkmsRespondWithRetrievalMethodId)));
        return(-1);
    }

    if(xmlSecXkmsRespondWithIdsRegister(xmlSecXkmsRespondWithX509CertId) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsRespondWithIdsRegister",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(xmlSecXkmsRespondWithX509CertId)));
        return(-1);
    }

    if(xmlSecXkmsRespondWithIdsRegister(xmlSecXkmsRespondWithX509ChainId) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsRespondWithIdsRegister",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(xmlSecXkmsRespondWithX509ChainId)));
        return(-1);
    }

    if(xmlSecXkmsRespondWithIdsRegister(xmlSecXkmsRespondWithX509CRLId) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsRespondWithIdsRegister",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(xmlSecXkmsRespondWithX509CRLId)));
        return(-1);
    }

    /* TODO: OCSP, PGP, PGPWeb, SPKI */
    /*
    if(xmlSecXkmsRespondWithIdsRegister(xmlSecXkmsRespondWithPGPId) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsRespondWithIdsRegister",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(xmlSecXkmsRespondWithPGPId)));
        return(-1);
    }

    if(xmlSecXkmsRespondWithIdsRegister(xmlSecXkmsRespondWithSPKIId) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsRespondWithIdsRegister",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(xmlSecXkmsRespondWithSPKIId)));
        return(-1);
    }
    */
    return(0);
}


/************************************************************************
 *
 * XKMS RespondWith Klass
 *
 ************************************************************************/
/**
 * xmlSecXkmsRespondWithNodeRead:
 * @id:         the RespondWith class.
 * @ctx:        the XKMS request processing context.
 * @node:       the pointer to <xkms:RespondWith/> node.
 *
 * Reads the content of the <xkms:RespondWith/> @node.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecXkmsRespondWithNodeRead(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
                              xmlNodePtr node) {
    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    if(id->readNode != NULL) {
        return((id->readNode)(id, ctx, node));
    }
    return(0);
}

/**
 * xmlSecXkmsRespondWithNodeWrite:
 * @id:         the RespondWith class.
 * @ctx:        the XKMS request processing context.
 * @node:       the pointer to <xkms:RespondWith/> node.
 *
 * Writes the content of the <xkms:RespondWith/> @node.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecXkmsRespondWithNodeWrite(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
                             xmlNodePtr node) {
    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    if(id->writeNode != NULL) {
        return((id->writeNode)(id, ctx, node));
    }
    return(0);
}

/**
 * xmlSecXkmsRespondWithDebugDump:
 * @id:         the RespondWith class.
 * @output:     the output file.
 *
 * Writes debug information about @id into the @output.
 */
void
xmlSecXkmsRespondWithDebugDump(xmlSecXkmsRespondWithId id, FILE* output) {
    xmlSecAssert(id != xmlSecXkmsRespondWithIdUnknown);
    xmlSecAssert(output != NULL);

    fprintf(output, "=== RespondWith: \"%s\" (href=\"%s\")\n",
        xmlSecErrorsSafeString(id->valueName),
        xmlSecErrorsSafeString(id->valueNs));
}

/**
 * xmlSecXkmsRespondWithDebugXmlDump:
 * @id:         the RespondWith class.
 * @output:     the output file.
 *
 * Writes debug information about @id into the @output in XML format.
 */
void
xmlSecXkmsRespondWithDebugXmlDump(xmlSecXkmsRespondWithId id, FILE* output) {
    xmlSecAssert(id != xmlSecXkmsRespondWithIdUnknown);
    xmlSecAssert(output != NULL);

    fprintf(output, "<RespondWith href=\"");
    xmlSecPrintXmlString(output, id->valueNs);
    fprintf(output, "\">");
    xmlSecPrintXmlString(output, id->valueName);
    fprintf(output, "</RespondWith>\n");
}

int
xmlSecXkmsRespondWithDefaultNodeRead(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
                            xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    ret = xmlSecXkmsRespondWithIdListFind(&(ctx->respWithList), id);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
                    "xmlSecXkmsRespondWithIdListFind",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    } else if(ret > 0) {
        /* do nothing, we already have it in the list */
        return(0);
    }

    ret = xmlSecPtrListAdd(&(ctx->respWithList), id);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
                    "xmlSecPtrListAdd",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

int
xmlSecXkmsRespondWithDefaultNodeWrite(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
                            xmlNodePtr node) {
    xmlNodePtr cur;

    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(id->nodeName != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = xmlSecAddChild(node, id->nodeName, id->nodeNs);
    if(cur == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
                    "xmlSecAddChild",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "node=%s",
                    xmlSecErrorsSafeString(id->nodeName));
        return(-1);
    }

    return(0);
}

/************************************************************************
 *
 * XKMS RespondWith Klass List
 *
 ************************************************************************/
static xmlSecPtrListKlass xmlSecXkmsRespondWithIdListKlass = {
    BAD_CAST "respond-with-ids-list",
    NULL,                                                               /* xmlSecPtrDuplicateItemMethod duplicateItem; */
    NULL,                                                               /* xmlSecPtrDestroyItemMethod destroyItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecXkmsRespondWithDebugDump,       /* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecXkmsRespondWithDebugXmlDump,    /* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

xmlSecPtrListId
xmlSecXkmsRespondWithIdListGetKlass(void) {
    return(&xmlSecXkmsRespondWithIdListKlass);
}

int
xmlSecXkmsRespondWithIdListFind(xmlSecPtrListPtr list, xmlSecXkmsRespondWithId id) {
    xmlSecSize i, size;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecXkmsRespondWithIdListId), -1);
    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        if((xmlSecXkmsRespondWithId)xmlSecPtrListGetItem(list, i) == id) {
            return(1);
        }
    }
    return(0);
}

xmlSecXkmsRespondWithId
xmlSecXkmsRespondWithIdListFindByNodeValue(xmlSecPtrListPtr list, xmlNodePtr node) {
    xmlSecXkmsRespondWithId result = xmlSecXkmsRespondWithIdUnknown;
    xmlSecXkmsRespondWithId id;
    xmlChar* content;
    xmlChar* qnameLocalPart = NULL;
    xmlChar* qnamePrefix = NULL;
    const xmlChar* qnameHref;
    xmlNsPtr ns;
    xmlSecSize i, size;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecXkmsRespondWithIdListId), xmlSecXkmsRespondWithIdUnknown);
    xmlSecAssert2(node != NULL, xmlSecXkmsRespondWithIdUnknown);

    content = xmlNodeGetContent(node);
    if(content == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlNodeGetContent",
                    XMLSEC_ERRORS_R_XML_FAILED,
                    "node=%s",
                    xmlSecErrorsSafeString(node->name));
        return(xmlSecXkmsRespondWithIdUnknown);
    }

    qnameLocalPart = (xmlChar*)xmlStrchr(content, ':');
    if(qnameLocalPart != NULL) {
        qnamePrefix = content;
        *(qnameLocalPart++) = '\0';
    } else {
        qnamePrefix = NULL;
        qnameLocalPart = content;
    }

    /* search namespace href */
    ns = xmlSearchNs(node->doc, node, qnamePrefix);
    if((ns == NULL) && (qnamePrefix != NULL)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSearchNs",
                    XMLSEC_ERRORS_R_XML_FAILED,
                    "node=%s,qnamePrefix=%s",
                    xmlSecErrorsSafeString(node->name),
                    xmlSecErrorsSafeString(qnamePrefix));
        xmlFree(content);
        return(xmlSecXkmsRespondWithIdUnknown);
    }
    qnameHref = (ns != NULL) ? ns->href : BAD_CAST NULL;

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        id = (xmlSecXkmsRespondWithId)xmlSecPtrListGetItem(list, i);
        if((id !=  xmlSecXkmsRespondWithIdUnknown) &&
                xmlStrEqual(id->valueName, qnameLocalPart) &&
                xmlStrEqual(id->valueNs, qnameHref)) {
            result = id;
            break;
        }
    }

    xmlFree(content);
    return(result);
}

int
xmlSecXkmsRespondWithIdListWrite(xmlSecPtrListPtr list, xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlSecXkmsRespondWithId id;
    xmlSecSize i, size;
    int ret;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecXkmsRespondWithIdListId), -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        id = (xmlSecXkmsRespondWithId)xmlSecPtrListGetItem(list, i);
        if(id !=  xmlSecXkmsRespondWithIdUnknown) {
            ret = xmlSecXkmsRespondWithNodeWrite(id, ctx, node);
            if(ret < 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
                            "xmlSecXkmsRespondWithNodeWrite",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
        }
    }

    return(0);
}

/********************************************************************
 *
 * XML Sec Library RespondWith Ids
 *
 *******************************************************************/
static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithKeyNameKlass = {
    xmlSecRespondWithKeyName,                   /* const xmlChar* valueName; */
    xmlSecXkmsNs,                               /* const xmlChar* valueNs; */
    xmlSecNodeKeyName,                          /* const xmlChar* nodeName; */
    xmlSecDSigNs,                               /* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithDefaultNodeRead,       /* xmlSecXkmsRespondWithNodeReadMethod readNode; */
    xmlSecXkmsRespondWithDefaultNodeWrite,      /* xmlSecXkmsRespondWithNodeWriteMethod writeNode; */
    NULL,                                       /* void* reserved1; */
    NULL                                        /* void* reserved2; */
};

/**
 * xmlSecXkmsRespondWithKeyNameGetKlass:
 *
 * The respond with KeyName klass.
 *
 * Returns: respond with KeyName klass.
 */
xmlSecXkmsRespondWithId
xmlSecXkmsRespondWithKeyNameGetKlass(void) {
    return(&xmlSecXkmsRespondWithKeyNameKlass);
}



static  int             xmlSecXkmsRespondWithKeyValueNodeRead   (xmlSecXkmsRespondWithId id,
                                                                 xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithKeyValueKlass = {
    xmlSecRespondWithKeyValue,                  /* const xmlChar* valueName; */
    xmlSecXkmsNs,                               /* const xmlChar* valueNs; */
    xmlSecNodeKeyValue,                         /* const xmlChar* nodeName; */
    xmlSecDSigNs,                               /* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithKeyValueNodeRead,      /* xmlSecXkmsRespondWithNodeReadMethod readNode; */
    xmlSecXkmsRespondWithDefaultNodeWrite,      /* xmlSecXkmsRespondWithNodeWriteMethod writeNode; */
    NULL,                                       /* void* reserved1; */
    NULL                                        /* void* reserved2; */
};

/**
 * xmlSecXkmsRespondWithKeyValueGetKlass:
 *
 * The respond with KeyValue klass.
 *
 * Returns: respond with KeyValue klass.
 */
xmlSecXkmsRespondWithId
xmlSecXkmsRespondWithKeyValueGetKlass(void) {
    return(&xmlSecXkmsRespondWithKeyValueKlass);
}

static  int
xmlSecXkmsRespondWithKeyValueNodeRead(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
                                      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithKeyValueId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultNodeRead(id, ctx, node);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
                    "xmlSecXkmsRespondWithDefaultNodeRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* and now set some parameters in the ctx to look for a public or private
     * key and to write a public key
     */
    ctx->keyInfoReadCtx.keyReq.keyType  |= (xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate);
    ctx->keyInfoWriteCtx.keyReq.keyType |= xmlSecKeyDataTypePublic;

    return(0);
}

static  int             xmlSecXkmsRespondWithPrivateKeyNodeRead (xmlSecXkmsRespondWithId id,
                                                                 xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithPrivateKeyKlass = {
    xmlSecRespondWithPrivateKey,                /* const xmlChar* valueName; */
    xmlSecXkmsNs,                               /* const xmlChar* valueNs; */
    xmlSecNodeKeyValue,                         /* const xmlChar* nodeName; */
    xmlSecDSigNs,                               /* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithPrivateKeyNodeRead,    /* xmlSecXkmsRespondWithNodeReadMethod readNode; */
    xmlSecXkmsRespondWithDefaultNodeWrite,      /* xmlSecXkmsRespondWithNodeWriteMethod writeNode; */
    NULL,                                       /* void* reserved1; */
    NULL                                        /* void* reserved2; */
};

/**
 * xmlSecXkmsRespondWithPrivateKeyGetKlass:
 *
 * The respond with PrivateKey klass.
 *
 * Returns: respond with PrivateKey klass.
 */
xmlSecXkmsRespondWithId
xmlSecXkmsRespondWithPrivateKeyGetKlass(void) {
    return(&xmlSecXkmsRespondWithPrivateKeyKlass);
}

static  int
xmlSecXkmsRespondWithPrivateKeyNodeRead(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
                                      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithPrivateKeyId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultNodeRead(id, ctx, node);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
                    "xmlSecXkmsRespondWithDefaultNodeRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* and now set some parameters in the ctx to look for a private
     * key and to write a private key
     */
    ctx->keyInfoReadCtx.keyReq.keyType  |= xmlSecKeyDataTypePrivate;
    ctx->keyInfoWriteCtx.keyReq.keyType |= xmlSecKeyDataTypePrivate;

    return(0);
}

static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithRetrievalMethodKlass = {
    xmlSecRespondWithRetrievalMethod,           /* const xmlChar* valueName; */
    xmlSecXkmsNs,                               /* const xmlChar* valueNs; */
    xmlSecNodeRetrievalMethod,                  /* const xmlChar* nodeName; */
    xmlSecDSigNs,                               /* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithDefaultNodeRead,       /* xmlSecXkmsRespondWithNodeReadMethod readNode; */
    xmlSecXkmsRespondWithDefaultNodeWrite,      /* xmlSecXkmsRespondWithNodeWriteMethod writeNode; */
    NULL,                                       /* void* reserved1; */
    NULL                                        /* void* reserved2; */
};

/**
 * xmlSecXkmsRespondWithRetrievalMethodGetKlass:
 *
 * The respond with RetrievalMethod klass.
 *
 * Returns: respond with RetrievalMethod klass.
 */
xmlSecXkmsRespondWithId
xmlSecXkmsRespondWithRetrievalMethodGetKlass(void) {
    return(&xmlSecXkmsRespondWithRetrievalMethodKlass);
}



static  int             xmlSecXkmsRespondWithX509CertNodeRead   (xmlSecXkmsRespondWithId id,
                                                                 xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithX509CertKlass = {
    xmlSecRespondWithX509Cert,                  /* const xmlChar* valueName; */
    xmlSecXkmsNs,                               /* const xmlChar* valueNs; */
    xmlSecNodeX509Data,                         /* const xmlChar* nodeName; */
    xmlSecDSigNs,                               /* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithX509CertNodeRead,      /* xmlSecXkmsRespondWithNodeReadMethod readNode; */
    xmlSecXkmsRespondWithDefaultNodeWrite,      /* xmlSecXkmsRespondWithNodeWriteMethod writeNode; */
    NULL,                                       /* void* reserved1; */
    NULL                                        /* void* reserved2; */
};

/**
 * xmlSecXkmsRespondWithX509CertGetKlass:
 *
 * The respond with X509Cert klass.
 *
 * Returns: respond with X509Cert klass.
 */
xmlSecXkmsRespondWithId
xmlSecXkmsRespondWithX509CertGetKlass(void) {
    return(&xmlSecXkmsRespondWithX509CertKlass);
}

static  int
xmlSecXkmsRespondWithX509CertNodeRead(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
                                      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithX509CertId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultNodeRead(id, ctx, node);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
                    "xmlSecXkmsRespondWithDefaultNodeRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

static  int             xmlSecXkmsRespondWithX509ChainNodeRead  (xmlSecXkmsRespondWithId id,
                                                                 xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithX509ChainKlass = {
    xmlSecRespondWithX509Chain,                 /* const xmlChar* valueName; */
    xmlSecXkmsNs,                               /* const xmlChar* valueNs; */
    xmlSecNodeX509Data,                         /* const xmlChar* nodeName; */
    xmlSecDSigNs,                               /* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithX509ChainNodeRead,     /* xmlSecXkmsRespondWithNodeReadMethod readNode; */
    xmlSecXkmsRespondWithDefaultNodeWrite,      /* xmlSecXkmsRespondWithNodeWriteMethod writeNode; */
    NULL,                                       /* void* reserved1; */
    NULL                                        /* void* reserved2; */
};

/**
 * xmlSecXkmsRespondWithX509ChainGetKlass:
 *
 * The respond with X509Chain klass.
 *
 * Returns: respond with X509Chain klass.
 */
xmlSecXkmsRespondWithId
xmlSecXkmsRespondWithX509ChainGetKlass(void) {
    return(&xmlSecXkmsRespondWithX509ChainKlass);
}

static  int
xmlSecXkmsRespondWithX509ChainNodeRead(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
                                      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithX509ChainId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultNodeRead(id, ctx, node);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
                    "xmlSecXkmsRespondWithDefaultNodeRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

static  int             xmlSecXkmsRespondWithX509CRLNodeRead    (xmlSecXkmsRespondWithId id,
                                                                 xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithX509CRLKlass = {
    xmlSecRespondWithX509CRL,                   /* const xmlChar* valueName; */
    xmlSecXkmsNs,                               /* const xmlChar* valueNs; */
    xmlSecNodeX509Data,                         /* const xmlChar* nodeName; */
    xmlSecDSigNs,                               /* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithX509CRLNodeRead,       /* xmlSecXkmsRespondWithNodeReadMethod readNode; */
    xmlSecXkmsRespondWithDefaultNodeWrite,      /* xmlSecXkmsRespondWithNodeWriteMethod writeNode; */
    NULL,                                       /* void* reserved1; */
    NULL                                        /* void* reserved2; */
};

/**
 * xmlSecXkmsRespondWithX509CRLGetKlass:
 *
 * The respond with X509CRL klass.
 *
 * Returns: respond with X509CRL klass.
 */
xmlSecXkmsRespondWithId
xmlSecXkmsRespondWithX509CRLGetKlass(void) {
    return(&xmlSecXkmsRespondWithX509CRLKlass);
}

static  int
xmlSecXkmsRespondWithX509CRLNodeRead(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
                                      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithX509CRLId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultNodeRead(id, ctx, node);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
                    "xmlSecXkmsRespondWithDefaultNodeRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithPGPKlass = {
    xmlSecRespondWithPGP,                       /* const xmlChar* valueName; */
    xmlSecXkmsNs,                               /* const xmlChar* valueNs; */
    xmlSecNodePGPData,                          /* const xmlChar* nodeName; */
    xmlSecDSigNs,                               /* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithDefaultNodeRead,       /* xmlSecXkmsRespondWithNodeReadMethod readNode; */
    xmlSecXkmsRespondWithDefaultNodeWrite,      /* xmlSecXkmsRespondWithNodeWriteMethod writeNode; */
    NULL,                                       /* void* reserved1; */
    NULL                                        /* void* reserved2; */
};

/**
 * xmlSecXkmsRespondWithPGPGetKlass:
 *
 * The respond with PGP klass.
 *
 * Returns: respond with PGP klass.
 */
xmlSecXkmsRespondWithId
xmlSecXkmsRespondWithPGPGetKlass(void) {
    return(&xmlSecXkmsRespondWithPGPKlass);
}

static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithSPKIKlass = {
    xmlSecRespondWithSPKI,                      /* const xmlChar* valueName; */
    xmlSecXkmsNs,                               /* const xmlChar* valueNs; */
    xmlSecNodeSPKIData,                         /* const xmlChar* nodeName; */
    xmlSecDSigNs,                               /* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithDefaultNodeRead,       /* xmlSecXkmsRespondWithNodeReadMethod readNode; */
    xmlSecXkmsRespondWithDefaultNodeWrite,      /* xmlSecXkmsRespondWithNodeWriteMethod writeNode; */
    NULL,                                       /* void* reserved1; */
    NULL                                        /* void* reserved2; */
};

/**
 * xmlSecXkmsRespondWithSPKIGetKlass:
 *
 * The respond with SPKI klass.
 *
 * Returns: respond with SPKI klass.
 */
xmlSecXkmsRespondWithId
xmlSecXkmsRespondWithSPKIGetKlass(void) {
    return(&xmlSecXkmsRespondWithSPKIKlass);
}

/**************************************************************************
 *
 * Global xmlSecXkmsServerRequestIds list functions
 *
 *************************************************************************/
static xmlSecPtrList xmlSecAllXkmsServerRequestIds;


/**
 * xmlSecXkmsServerRequestIdsGet:
 *
 * Gets global registered ServerRequest klasses list.
 *
 * Returns: the pointer to list of all registered ServerRequest klasses.
 */
xmlSecPtrListPtr
xmlSecXkmsServerRequestIdsGet(void) {
    return(&xmlSecAllXkmsServerRequestIds);
}

/**
 * xmlSecXkmsServerRequestIdsInit:
 *
 * Initializes the ServerRequest klasses. This function is called from the
 * #xmlSecInit function and the application should not call it directly.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecXkmsServerRequestIdsInit(void) {
    int ret;

    ret = xmlSecPtrListInitialize(xmlSecXkmsServerRequestIdsGet(), xmlSecXkmsServerRequestIdListId);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecPtrListPtrInitialize",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "xmlSecXkmsServerRequestIdListId");
        return(-1);
    }

    ret = xmlSecXkmsServerRequestIdsRegisterDefault();
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerRequestIdsRegisterDefault",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

/**
 *  xmlSecXkmsServerRequestIdsShutdown:
 *
 * Shuts down the keys data klasses. This function is called from the
 * #xmlSecShutdown function and the application should not call it directly.
 */
void
xmlSecXkmsServerRequestIdsShutdown(void) {
    xmlSecPtrListFinalize(xmlSecXkmsServerRequestIdsGet());
}

/**
 * xmlSecXkmsServerRequestIdsRegister:
 * @id:         the ServerRequest klass.
 *
 * Registers @id in the global list of ServerRequest klasses.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecXkmsServerRequestIdsRegister(xmlSecXkmsServerRequestId id) {
    int ret;

    xmlSecAssert2(id != xmlSecXkmsServerRequestIdUnknown, -1);

    ret = xmlSecPtrListAdd(xmlSecXkmsServerRequestIdsGet(), (xmlSecPtr)id);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecPtrListAdd",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "ServerRequest=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsServerRequestKlassGetName(id)));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecXkmsServerRequestIdsRegisterDefault:
 *
 * Registers default (implemented by XML Security Library)
 * ServerRequest klasses: KeyName, KeyValue,...
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecXkmsServerRequestIdsRegisterDefault(void) {
    if(xmlSecXkmsServerRequestIdsRegister(xmlSecXkmsServerRequestResultId) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerRequestIdsRegister",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsServerRequestKlassGetName(xmlSecXkmsServerRequestResultId)));
        return(-1);
    }

    if(xmlSecXkmsServerRequestIdsRegister(xmlSecXkmsServerRequestStatusId) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerRequestIdsRegister",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsServerRequestKlassGetName(xmlSecXkmsServerRequestStatusId)));
        return(-1);
    }

    if(xmlSecXkmsServerRequestIdsRegister(xmlSecXkmsServerRequestCompoundId) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerRequestIdsRegister",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsServerRequestKlassGetName(xmlSecXkmsServerRequestCompoundId)));
        return(-1);
    }

    if(xmlSecXkmsServerRequestIdsRegister(xmlSecXkmsServerRequestLocateId) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerRequestIdsRegister",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsServerRequestKlassGetName(xmlSecXkmsServerRequestLocateId)));
        return(-1);
    }

    if(xmlSecXkmsServerRequestIdsRegister(xmlSecXkmsServerRequestValidateId) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerRequestIdsRegister",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "name=%s",
                    xmlSecErrorsSafeString(xmlSecXkmsServerRequestKlassGetName(xmlSecXkmsServerRequestValidateId)));
        return(-1);
    }

    return(0);
}


/************************************************************************
 *
 * XKMS ServerRequest Klass
 *
 ************************************************************************/
/**
 * xmlSecXkmsServerRequestNodeRead:
 * @id:         the ServerRequest class.
 * @ctx:        the XKMS request processing context.
 * @node:       the pointer to <xkms:ServerRequest/> node.
 *
 * Reads the content of the <xkms:ServerRequest/> @node.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecXkmsServerRequestNodeRead(xmlSecXkmsServerRequestId id, xmlSecXkmsServerCtxPtr ctx,
                              xmlNodePtr node) {
    xmlSecAssert2(id != xmlSecXkmsServerRequestIdUnknown, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    if(id->readNode != NULL) {
        return((id->readNode)(id, ctx, node));
    }
    return(0);
}

/**
 * xmlSecXkmsServerExecute:
 * @id:         the ServerRequest class.
 * @ctx:        the XKMS request processing context.
 *
 * Executes XKMS server request.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecXkmsServerRequestExecute(xmlSecXkmsServerRequestId id, xmlSecXkmsServerCtxPtr ctx) {
    xmlSecAssert2(id != xmlSecXkmsServerRequestIdUnknown, -1);
    xmlSecAssert2(ctx != NULL, -1);

    if(id->execute != NULL) {
        return((id->execute)(id, ctx));
    }
    return(0);
}


/**
 * xmlSecXkmsServerResponseNodeWrite:
 * @id:         the ServerRequest class.
 * @ctx:        the XKMS request processing context.
 * @doc:        the pointer to response parent XML document (might be NULL).
 * @node:       the pointer to response parent XML node (might be NULL).
 *
 * Writes XKMS response from context to a newly created node. Caller is
 * responsible for adding the returned node to the XML document.
 *
 * Returns: pointer to newly created XKMS response node or NULL
 * if an error occurs.
 */
xmlNodePtr
xmlSecXkmsServerRequestNodeWrite(xmlSecXkmsServerRequestId id, xmlSecXkmsServerCtxPtr ctx,
                                 xmlDocPtr doc, xmlNodePtr node) {
    xmlNodePtr respNode;
    int ret;

    xmlSecAssert2(id != xmlSecXkmsServerRequestIdUnknown, NULL);
    xmlSecAssert2(ctx != NULL, NULL);

    /* create the response root node */
    if(node == NULL) {
        xmlNsPtr ns;

        respNode = xmlNewDocNode(doc, NULL, id->resultNodeName, NULL);
        if(respNode == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlNewDocNode",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        "node=%s",
                        xmlSecErrorsSafeString(id->resultNodeName));
            return(NULL);
        }
        ns = xmlNewNs(respNode, id->resultNodeNs, NULL);
        if(ns == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlNewNs",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        "ns=%s",
                        xmlSecErrorsSafeString(id->resultNodeNs));
            xmlFreeNode(respNode);
            return(NULL);
        }
        xmlSetNs(respNode, ns);
    } else {
        respNode = xmlSecAddChild(node, id->resultNodeName, id->resultNodeNs);
        if(respNode == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecAddChild",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "node=%s",
                        xmlSecErrorsSafeString(id->resultNodeName));
            return(NULL);
        }
    }

    if(id->writeNode != NULL) {
        ret = (id->writeNode)(id, ctx, respNode);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "writeNode",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "node=%s",
                        xmlSecErrorsSafeString(id->resultNodeName));
            xmlFreeNode(respNode);
            return(NULL);
        }
    }

    return(respNode);
}

/**
 * xmlSecXkmsServerRequestDebugDump:
 * @id:                 the ServerRequest class.
 * @output:             the output file.
 *
 * Writes debug information about @id into the @output.
 */
void
xmlSecXkmsServerRequestDebugDump(xmlSecXkmsServerRequestId id, FILE* output) {
    xmlSecAssert(id != xmlSecXkmsServerRequestIdUnknown);
    xmlSecAssert(output != NULL);

    fprintf(output, "=== ServerRequest: %s\n", xmlSecErrorsSafeString(id->name));
}

/**
 * xmlSecXkmsServerRequestDebugXmlDump:
 * @id:                 the ServerRequest class.
 * @output:             the output file.
 *
 * Writes debug information about @id into the @output in XML format.
 */
void
xmlSecXkmsServerRequestDebugXmlDump(xmlSecXkmsServerRequestId id, FILE* output) {
    xmlSecAssert(id != xmlSecXkmsServerRequestIdUnknown);
    xmlSecAssert(output != NULL);

    fprintf(output, "<ServerRequest>");
    xmlSecPrintXmlString(output, id->name);
    fprintf(output, "</ServerRequest>\n");
}

/************************************************************************
 *
 * XKMS ServerRequest Klass List
 *
 ************************************************************************/
static xmlSecPtrListKlass xmlSecXkmsServerRequestIdListKlass = {
    BAD_CAST "xkms-server-request-ids-list",
    NULL,                                                               /* xmlSecPtrDuplicateItemMethod duplicateItem; */
    NULL,                                                               /* xmlSecPtrDestroyItemMethod destroyItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecXkmsServerRequestDebugDump,     /* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecXkmsServerRequestDebugXmlDump,  /* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

xmlSecPtrListId
xmlSecXkmsServerRequestIdListGetKlass(void) {
    return(&xmlSecXkmsServerRequestIdListKlass);
}

int
xmlSecXkmsServerRequestIdListFind(xmlSecPtrListPtr list, xmlSecXkmsServerRequestId id) {
    xmlSecSize i, size;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecXkmsServerRequestIdListId), -1);
    xmlSecAssert2(id != xmlSecXkmsServerRequestIdUnknown, -1);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        if((xmlSecXkmsServerRequestId)xmlSecPtrListGetItem(list, i) == id) {
            return(1);
        }
    }
    return(0);
}

xmlSecXkmsServerRequestId
xmlSecXkmsServerRequestIdListFindByName(xmlSecPtrListPtr list, const xmlChar* name) {
    xmlSecXkmsServerRequestId id;
    xmlSecSize i, size;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecXkmsServerRequestIdListId), xmlSecXkmsServerRequestIdUnknown);
    xmlSecAssert2(name != NULL, xmlSecXkmsServerRequestIdUnknown);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        id = (xmlSecXkmsServerRequestId)xmlSecPtrListGetItem(list, i);
        if((id !=  xmlSecXkmsServerRequestIdUnknown) && xmlStrEqual(id->name, name)) {
            return(id);
        }
    }
    return(xmlSecXkmsServerRequestIdUnknown);
}

xmlSecXkmsServerRequestId
xmlSecXkmsServerRequestIdListFindByNode(xmlSecPtrListPtr list, xmlNodePtr node) {
    xmlSecXkmsServerRequestId id;
    xmlSecSize i, size;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecXkmsServerRequestIdListId), xmlSecXkmsServerRequestIdUnknown);
    xmlSecAssert2(node != NULL, xmlSecXkmsServerRequestIdUnknown);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        id = (xmlSecXkmsServerRequestId)xmlSecPtrListGetItem(list, i);
        if((id !=  xmlSecXkmsServerRequestIdUnknown) &&
            xmlSecCheckNodeName(node, id->requestNodeName, id->requestNodeNs)) {

            return(id);
        }
    }
    return(xmlSecXkmsServerRequestIdUnknown);
}

/********************************************************************
 *
 * XML Sec Library ServerRequest Ids
 *
 *******************************************************************/


/********************************************************************
 *
 * Result response
 *
 *******************************************************************/
static int              xmlSecXkmsServerRequestResultNodeWrite  (xmlSecXkmsServerRequestId id,
                                                                 xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);

static xmlSecXkmsServerRequestKlass xmlSecXkmsServerRequestResultKlass = {
    xmlSecXkmsServerRequestResultName,          /* const xmlChar* name; */
    NULL,                                       /* const xmlChar* requestNodeName; */
    NULL,                                       /* const xmlChar* requestNodeNs; */
    xmlSecNodeResult,                           /* const xmlChar* responseNodeName; */
    xmlSecXkmsNs,                               /* const xmlChar* responseNodeNs; */
    0,                                          /* xmlSecBitMask flags; */
    NULL,                                       /* xmlSecXkmsServerRequestNodeReadMethod readNode; */
    xmlSecXkmsServerRequestResultNodeWrite,     /* xmlSecXkmsServerRequestNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecXkmsServerRequestExecuteMethod execute; */
    NULL,                                       /* void* reserved1; */
    NULL                                        /* void* reserved2; */
};

/**
 * xmlSecXkmsServerRequestResultGetKlass:
 *
 * The Result response klass.
 *
 * Returns: Result response klass.
 */
xmlSecXkmsServerRequestId
xmlSecXkmsServerRequestResultGetKlass(void) {
    return(&xmlSecXkmsServerRequestResultKlass);
}

static int
xmlSecXkmsServerRequestResultNodeWrite(xmlSecXkmsServerRequestId id, xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsServerRequestResultId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* set missing parameters (if any) */
    if(ctx->service == NULL) {
        ctx->service = xmlStrdup((ctx->expectedService != NULL) ? ctx->expectedService : BAD_CAST "");
        if(ctx->service == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlStrdup",
                        XMLSEC_ERRORS_R_MALLOC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    }

    /* first write the "parent" type */
    ret = xmlSecXkmsServerCtxResultTypeNodeWrite(ctx, node);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxResultTypeNodeWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

/********************************************************************
 *
 * StatusRequest/StatusResponse
 *
 *******************************************************************/
static int              xmlSecXkmsServerRequestStatusNodeRead   (xmlSecXkmsServerRequestId id,
                                                                 xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static int              xmlSecXkmsServerRequestStatusNodeWrite  (xmlSecXkmsServerRequestId id,
                                                                 xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);

static xmlSecXkmsServerRequestKlass xmlSecXkmsServerRequestStatusKlass = {
    xmlSecXkmsServerRequestStatusName,          /* const xmlChar* name; */
    xmlSecNodeStatusRequest,                    /* const xmlChar* requestNodeName; */
    xmlSecXkmsNs,                               /* const xmlChar* requestNodeNs; */
    xmlSecNodeStatusResult,                     /* const xmlChar* responseNodeName; */
    xmlSecXkmsNs,                               /* const xmlChar* responseNodeNs; */
    0,                                          /* xmlSecBitMask flags; */
    xmlSecXkmsServerRequestStatusNodeRead,      /* xmlSecXkmsServerRequestNodeReadMethod readNode; */
    xmlSecXkmsServerRequestStatusNodeWrite,     /* xmlSecXkmsServerRequestNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecXkmsServerRequestExecuteMethod execute; */
    NULL,                                       /* void* reserved1; */
    NULL                                        /* void* reserved2; */
};

/**
 * xmlSecXkmsServerRequestStatusGetKlass:
 *
 * The StatusRequest klass.
 *
 * Returns: StatusRequest klass.
 */
xmlSecXkmsServerRequestId
xmlSecXkmsServerRequestStatusGetKlass(void) {
    return(&xmlSecXkmsServerRequestStatusKlass);
}

/**
 *
 *  <xkms:StatusRequest Id Service Nonce? OriginalRequestId? ResponseLimit? ResponseId?>
 *      <ds:Signature>?
 *      <xkms:MessageExtension>*
 *      (<xkms:OpaqueClientData>
 *          <xkms:OpaqueData>?
 *      )?
 *      <xkms:ResponseMechanism>*
 *      <xkms:RespondWith>*
 *      <xkms:PendingNotification Mechanism Identifier>?
 *
 * XML Schema:
 *    <!-- StatusRequest -->
 *    <element name="StatusRequest" type="xkms:StatusRequestType"/>
 *    <complexType name="StatusRequestType">
 *        <complexContent>
 *            <extension base="xkms:PendingRequestType"/>
 *        </complexContent>
 *    </complexType>
 *    <!-- /StatusRequest -->
 */
static int
xmlSecXkmsServerRequestStatusNodeRead(xmlSecXkmsServerRequestId id, xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(id == xmlSecXkmsServerRequestStatusId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = node;

    /* first read "parent" type */
    ret = xmlSecXkmsServerCtxPendingRequestNodeRead(ctx, &cur);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxPendingRequestNodeRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* check that there is nothing after the last node */
    if(cur != NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
                    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

/**
 *
 *  <xkms:StatusResult Id Service Nonce? ResultMajor ResultMinor? RequestId? Success? Failure? Pending?>
 *      <ds:Signature>?
 *      <xkms:MessageExtension>*
 *      (<xkms:OpaqueClientData>
 *          <xkms:OpaqueData>?
 *      )?
 *      <xkms:RequestSignatureValue>*
 *
 * XML Schema:
 *
 *    <!-- StatusResult -->
 *    <element name="StatusResult" type="xkms:StatusResultType"/>
 *    <complexType name="StatusResultType">
 *        <complexContent>
 *            <extension base="xkms:ResultType">
 *                <attribute name="Success" type="integer" use="optional"/>
 *                <attribute name="Failure" type="integer" use="optional"/>
 *                <attribute name="Pending" type="integer" use="optional"/>
 *            </extension>
 *        </complexContent>
 *    </complexType>
 *    <!-- /StatusResult --> *
 */
static int
xmlSecXkmsServerRequestStatusNodeWrite(xmlSecXkmsServerRequestId id, xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsServerRequestStatusId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first write the "parent" type */
    ret = xmlSecXkmsServerCtxResultTypeNodeWrite(ctx, node);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxResultTypeNodeWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* todo: add optional StatusResult attributes */
    return(0);
}

/********************************************************************
 *
 * CompoundRequest/CompoundResponse
 *
 *******************************************************************/
static int              xmlSecXkmsServerRequestCompoundNodeRead (xmlSecXkmsServerRequestId id,
                                                                 xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static int              xmlSecXkmsServerRequestCompoundNodeWrite(xmlSecXkmsServerRequestId id,
                                                                 xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static int              xmlSecXkmsServerRequestCompoundExecute  (xmlSecXkmsServerRequestId id,
                                                                 xmlSecXkmsServerCtxPtr ctx);

static xmlSecXkmsServerRequestKlass xmlSecXkmsServerRequestCompoundKlass = {
    xmlSecXkmsServerRequestCompoundName,        /* const xmlChar* name; */
    xmlSecNodeCompoundRequest,                  /* const xmlChar* requestNodeName; */
    xmlSecXkmsNs,                               /* const xmlChar* requestNodeNs; */
    xmlSecNodeCompoundResult,                   /* const xmlChar* responseNodeName; */
    xmlSecXkmsNs,                               /* const xmlChar* responseNodeNs; */
    0,                                          /* xmlSecBitMask flags; */
    xmlSecXkmsServerRequestCompoundNodeRead,    /* xmlSecXkmsServerRequestNodeReadMethod readNode; */
    xmlSecXkmsServerRequestCompoundNodeWrite,   /* xmlSecXkmsServerRequestNodeWriteMethod writeNode; */
    xmlSecXkmsServerRequestCompoundExecute,     /* xmlSecXkmsServerRequestExecuteMethod execute; */
    NULL,                                       /* void* reserved1; */
    NULL                                        /* void* reserved2; */
};

/**
 * xmlSecXkmsServerRequestCompoundGetKlass:
 *
 * The CompoundRequest klass.
 *
 * Returns: CompoundRequest klass.
 */
xmlSecXkmsServerRequestId
xmlSecXkmsServerRequestCompoundGetKlass(void) {
    return(&xmlSecXkmsServerRequestCompoundKlass);
}

/**
 *  <xkms:CompoundRequest Id Service Nonce? OriginalRequestId? ResponseLimit?>
 *      <ds:Signature>?
 *      <xkms:MessageExtension>*
 *      (<xkms:OpaqueClientData>
 *          <xkms:OpaqueData>?
 *      )?
 *      <xkms:ResponseMechanism>*
 *      <xkms:RespondWith>*
 *      <xkms:PendingNotification Mechanism Identifier>?
 *      (
 *       <xkms:LocateRequest>?
 *       <xkms:ValidateRequest>?
 *       <xkms:RegisterRequest>?
 *       <xkms:ReissueRequest>?
 *       <xkms:RecoverRequest>?
 *       <xkms:RevokeRequest>?
 *      )*
 *
 * XML Schema:
 *
 *    <!-- CompoundRequest -->
 *    <element name="CompoundRequest" type="xkms:CompoundRequestType"/>
 *    <complexType name="CompoundRequestType">
 *        <complexContent>
 *            <extension base="xkms:RequestAbstractType">
 *                <choice maxOccurs="unbounded">
 *                    <element ref="xkms:LocateRequest"/>
 *                    <element ref="xkms:ValidateRequest"/>
 *                    <element ref="xkms:RegisterRequest"/>
 *                    <element ref="xkms:ReissueRequest"/>
 *                    <element ref="xkms:RecoverRequest"/>
 *                    <element ref="xkms:RevokeRequest"/>
 *                </choice>
 *            </extension>
 *        </complexContent>
 *    </complexType>
 *    <!-- /CompoundRequest -->
 */
static int
xmlSecXkmsServerRequestCompoundNodeRead(xmlSecXkmsServerRequestId id, xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlSecPtrListPtr serverRequestIdsList;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(id == xmlSecXkmsServerRequestCompoundId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = node;

    /* first read "parent" type */
    ret = xmlSecXkmsServerCtxRequestAbstractTypeNodeRead(ctx, &cur);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxRequestAbstractTypeNodeRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* create list for compound requests */
    xmlSecAssert2(ctx->compoundRequestContexts == NULL, -1);
    ctx->compoundRequestContexts = xmlSecPtrListCreate(xmlSecXkmsServerCtxPtrListId);
    if(ctx->compoundRequestContexts == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecPtrListCreate",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* get the list of enabled or all request klasses */
    if(xmlSecPtrListGetSize(&(ctx->enabledServerRequestIds)) > 0) {
        serverRequestIdsList = &(ctx->enabledServerRequestIds);
    } else {
        serverRequestIdsList = xmlSecXkmsServerRequestIdsGet();
    }
    xmlSecAssert2(serverRequestIdsList != NULL, -1);

    while(cur != NULL) {
        xmlSecXkmsServerCtxPtr ctxChild;

        /* create a new context */
        ctxChild = xmlSecXkmsServerCtxCreate(ctx->keyInfoReadCtx.keysMngr);
        if(ctxChild == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecXkmsServerCtxCreate",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }

        /* copy all settings from us */
        ret = xmlSecXkmsServerCtxCopyUserPref(ctxChild, ctx);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecXkmsServerCtxCopyUserPref",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxDestroy(ctxChild);
            return(-1);
        }

        /* add it to the list */
        ret = xmlSecPtrListAdd(ctx->compoundRequestContexts, ctxChild);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecPtrListAdd",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecXkmsServerCtxDestroy(ctxChild);
            return(-1);
        }

        /* and now process request from current node */
        ctxChild->requestId = xmlSecXkmsServerRequestIdListFindByNode(serverRequestIdsList, cur);
        if((ctxChild->requestId == xmlSecXkmsServerRequestIdUnknown) ||
           ((ctxChild->requestId->flags & XMLSEC_XKMS_SERVER_REQUEST_KLASS_ALLOWED_IN_COUMPOUND) == 0)) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecXkmsServerRequestIdListFindByNode",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "node=%s",
                        xmlSecErrorsSafeString(node->name));
            xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorMessageNotSupported);
            return(-1);
        }

        ret = xmlSecXkmsServerRequestNodeRead(ctxChild->requestId, ctxChild, cur);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecXkmsServerRequestNodeRead",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "request=%s",
                        xmlSecErrorsSafeString(xmlSecXkmsServerRequestKlassGetName(ctxChild->requestId)));
            xmlSecXkmsServerCtxSetResult(ctxChild, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorFailure);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* check that there is nothing after the last node */
    if(cur != NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
                    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

/**
 *  <xkms:CompoundResult Id Service Nonce? ResultMajor ResultMinor? RequestId?>
 *      <ds:Signature>?
 *      <xkms:MessageExtension>*
 *      (<xkms:OpaqueClientData>
 *          <xkms:OpaqueData>?
 *      )?
 *      <xkms:RequestSignatureValue>*
 *      (
 *       <xkms:LocateResult>?
 *       <xkms:ValidateResult>?
 *       <xkms:RegisterResult>?
 *       <xkms:ReissueResult>?
 *       <xkms:RecoverResult>?
 *       <xkms:RevokeResult>?
 *      )*
 *
 *
 * XML Schema:
 *
 *    <!-- CompoundResponse -->
 *    <element name="CompoundResult" type="xkms:CompoundResultType"/>
 *    <complexType name="CompoundResultType">
 *        <complexContent>
 *            <extension base="xkms:ResultType">
 *                <choice maxOccurs="unbounded">
 *                    <element ref="xkms:LocateResult"/>
 *                    <element ref="xkms:ValidateResult"/>
 *                    <element ref="xkms:RegisterResult"/>
 *                    <element ref="xkms:ReissueResult"/>
 *                    <element ref="xkms:RecoverResult"/>
 *                    <element ref="xkms:RevokeResult"/>
 *                </choice>
 *            </extension>
 *        </complexContent>
 *   </complexType>
 *   <!-- /CompoundResponse -->
 */
static int
xmlSecXkmsServerRequestCompoundNodeWrite(xmlSecXkmsServerRequestId id, xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsServerRequestCompoundId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* walk thru the list of chilren and pickup first error */
    if(ctx->compoundRequestContexts != NULL) {
        xmlSecSize pos;

        for(pos = 0; pos < xmlSecPtrListGetSize(ctx->compoundRequestContexts); pos++) {
            xmlSecXkmsServerCtxPtr ctxChild;

            ctxChild = (xmlSecXkmsServerCtxPtr)xmlSecPtrListGetItem(ctx->compoundRequestContexts, pos);
            if(ctxChild == NULL) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "xmlSecPtrListGetItem",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }

            if(ctxChild->resultMajor != xmlSecXkmsResultMajorSuccess) {
                xmlSecXkmsServerCtxSetResult(ctx, ctxChild->resultMajor, ctxChild->resultMinor);
                break;
            }
        }
    }

    /* first write the "parent" type */
    ret = xmlSecXkmsServerCtxResultTypeNodeWrite(ctx, node);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxResultTypeNodeWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* write compound result */
    if(ctx->compoundRequestContexts != NULL) {
        xmlSecSize pos;

        for(pos = 0; pos < xmlSecPtrListGetSize(ctx->compoundRequestContexts); pos++) {
            xmlSecXkmsServerCtxPtr ctxChild;
            xmlNodePtr cur;

            ctxChild = (xmlSecXkmsServerCtxPtr)xmlSecPtrListGetItem(ctx->compoundRequestContexts, pos);
            if(ctxChild == NULL) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "xmlSecPtrListGetItem",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }

            cur = xmlSecXkmsServerRequestNodeWrite(ctxChild->requestId, ctxChild, node->doc, node);
            if(cur == NULL) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "xmlSecXkmsServerRequestNodeWrite",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            "request=%s",
                            xmlSecErrorsSafeString(xmlSecXkmsServerRequestKlassGetName(ctxChild->requestId)));
                return(-1);
            }

            if(xmlSecAddChildNode(node, cur) == NULL) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "xmlSecAddChildNode",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                xmlFreeNode(cur);
                return(-1);
            }
        }
    }

    return(0);
}

static int
xmlSecXkmsServerRequestCompoundExecute(xmlSecXkmsServerRequestId id, xmlSecXkmsServerCtxPtr ctx) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsServerRequestCompoundId, -1);
    xmlSecAssert2(ctx != NULL, -1);

    if(ctx->compoundRequestContexts != NULL) {
        xmlSecSize pos;

        for(pos = 0; pos < xmlSecPtrListGetSize(ctx->compoundRequestContexts); pos++) {
            xmlSecXkmsServerCtxPtr ctxChild;

            ctxChild = (xmlSecXkmsServerCtxPtr)xmlSecPtrListGetItem(ctx->compoundRequestContexts, pos);
            if(ctxChild == NULL) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "xmlSecPtrListGetItem",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorReceiver, xmlSecXkmsResultMinorFailure);
                continue;
            }

            ret = xmlSecXkmsServerRequestExecute(ctxChild->requestId, ctxChild);
            if(ret < 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "xmlSecXkmsServerRequestExecute",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            "request=%s",
                            xmlSecErrorsSafeString(xmlSecXkmsServerRequestKlassGetName(ctxChild->requestId)));
                xmlSecXkmsServerCtxSetResult(ctxChild, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorFailure);
                continue;
            }
        }
    }

    return(0);
}


/********************************************************************
 *
 * LocateRequest/LocateResponse
 *
 *******************************************************************/
static int              xmlSecXkmsServerRequestLocateNodeRead   (xmlSecXkmsServerRequestId id,
                                                                 xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static int              xmlSecXkmsServerRequestLocateNodeWrite  (xmlSecXkmsServerRequestId id,
                                                                 xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static int              xmlSecXkmsServerRequestLocateExecute    (xmlSecXkmsServerRequestId id,
                                                                 xmlSecXkmsServerCtxPtr ctx);

static xmlSecXkmsServerRequestKlass xmlSecXkmsServerRequestLocateKlass = {
    xmlSecXkmsServerRequestLocateName,          /* const xmlChar* name; */
    xmlSecNodeLocateRequest,                    /* const xmlChar* requestNodeName; */
    xmlSecXkmsNs,                               /* const xmlChar* requestNodeNs; */
    xmlSecNodeLocateResult,                     /* const xmlChar* responseNodeName; */
    xmlSecXkmsNs,                               /* const xmlChar* responseNodeNs; */
    XMLSEC_XKMS_SERVER_REQUEST_KLASS_ALLOWED_IN_COUMPOUND,      /* xmlSecBitMask flags; */
    xmlSecXkmsServerRequestLocateNodeRead,      /* xmlSecXkmsServerRequestNodeReadMethod readNode; */
    xmlSecXkmsServerRequestLocateNodeWrite,     /* xmlSecXkmsServerRequestNodeWriteMethod writeNode; */
    xmlSecXkmsServerRequestLocateExecute,       /* xmlSecXkmsServerRequestExecuteMethod execute; */
    NULL,                                       /* void* reserved1; */
    NULL                                        /* void* reserved2; */
};

/**
 * xmlSecXkmsServerRequestLocateGetKlass:
 *
 * The LocateRequest klass.
 *
 * Returns: LocateRequest klass.
 */
xmlSecXkmsServerRequestId
xmlSecXkmsServerRequestLocateGetKlass(void) {
    return(&xmlSecXkmsServerRequestLocateKlass);
}

/**
 *  <xkms:LocateRequest Id Service Nonce? OriginalRequestId? ResponseLimit?>
 *      <ds:Signature>?
 *      <xkms:MessageExtension>*
 *      (<xkms:OpaqueClientData>
 *          <xkms:OpaqueData>?
 *      )?
 *      <xkms:ResponseMechanism>*
 *      <xkms:RespondWith>*
 *      <xkms:PendingNotification Mechanism Identifier>?
 *      <xkms:QueryKeyBinding Id?>
 *          <ds:KeyInfo>?
 *          <xkms:KeyUsage>?
 *          <xkms:KeyUsage>?
 *          <xkms:KeyUsage>?
 *          <xkms:UseKeyWith Application Identifier>*
 *          <xkms:TimeInstant Time>?
 *
 * XML Schema:
 *
 *    <!-- LocateRequest -->
 *    <element name="LocateRequest" type="xkms:LocateRequestType"/>
 *    <complexType name="LocateRequestType">
 *        <complexContent>
 *            <extension base="xkms:RequestAbstractType">
 *                <sequence>
 *                    <element ref="xkms:QueryKeyBinding"/>
 *                </sequence>
 *            </extension>
 *        </complexContent>
 *    </complexType>
 *    <!-- /LocateRequest -->
 */
static int
xmlSecXkmsServerRequestLocateNodeRead(xmlSecXkmsServerRequestId id, xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(id == xmlSecXkmsServerRequestLocateId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = node;

    /* first read "parent" type */
    ret = xmlSecXkmsServerCtxRequestAbstractTypeNodeRead(ctx, &cur);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxRequestAbstractTypeNodeRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* now read required <xkms:QueryKeyBinding/> node */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeQueryKeyBinding, xmlSecXkmsNs))) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
                    XMLSEC_ERRORS_R_INVALID_NODE,
                    "node=%s",
                    xmlSecErrorsSafeString(xmlSecNodeQueryKeyBinding));
        return(-1);
    }

    /* read <xkms:QueryKeyBinding/> node */
    ret = xmlSecXkmsServerCtxQueryKeyBindingNodeRead(ctx, cur);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxQueryKeyBindingNodeRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* check that there is nothing after the last node */
    if(cur != NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
                    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

/**
 *  <xkms:LocateResult Id Service Nonce? ResultMajor ResultMinor? RequestId?>
 *      <ds:Signature>?
 *      <xkms:MessageExtension>*
 *      (<xkms:OpaqueClientData>
 *          <xkms:OpaqueData>?
 *      )?
 *      <xkms:RequestSignatureValue>*
 *      (<xkms:UnverifiedKeyBinding Id?>
 *          <ds:KeyInfo>?
 *          <xkms:KeyUsage>?
 *          <xkms:KeyUsage>?
 *          <xkms:KeyUsage>?
 *          <xkms:UseKeyWith Application Identifier>*
 *          <xkms:ValidityInterval NotBefore NotOnOrAfter>?
 *      )*
 *
 * XML Schema:
 *    <!-- LocateResult -->
 *    <element name="LocateResult" type="xkms:LocateResultType"/>
 *    <complexType name="LocateResultType">
 *         <complexContent>
 *              <extension base="xkms:ResultType">
 *                   <sequence>
 *                       <element ref="xkms:UnverifiedKeyBinding" minOccurs="0"
 *                                maxOccurs="unbounded"/>
 *                   </sequence>
 *              </extension>
 *         </complexContent>
 *    </complexType>
 *    <!-- /LocateResult -->
 */
static int
xmlSecXkmsServerRequestLocateNodeWrite(xmlSecXkmsServerRequestId id, xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlSecSize pos, size;
    xmlSecKeyPtr key;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(id == xmlSecXkmsServerRequestLocateId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first write the "parent" type */
    ret = xmlSecXkmsServerCtxResultTypeNodeWrite(ctx, node);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxResultTypeNodeWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* write keys in <xkms:UnverifiedKeyBinding> nodes */
    size = xmlSecPtrListGetSize(&(ctx->keys));
    for(pos = 0; pos < size; ++pos) {
        key = (xmlSecKeyPtr)xmlSecPtrListGetItem(&(ctx->keys), pos);
        if(key == NULL) {
            continue;
        }

        cur = xmlSecAddChild(node, xmlSecNodeUnverifiedKeyBinding, xmlSecXkmsNs);
        if(cur == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecAddChild",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "node=%s",
                        xmlSecErrorsSafeString(xmlSecNodeUnverifiedKeyBinding));
            return(-1);
        }

        ret = xmlSecXkmsServerCtxUnverifiedKeyBindingNodeWrite(ctx, cur, key);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecXkmsServerCtxUnverifiedKeyBindingNodeWrite",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    }

    return(0);
}

static int
xmlSecXkmsServerRequestLocateExecute(xmlSecXkmsServerRequestId id, xmlSecXkmsServerCtxPtr ctx) {
    xmlSecKeyPtr key = NULL;
    int ret;

    xmlSecAssert2(id == xmlSecXkmsServerRequestLocateId, -1);
    xmlSecAssert2(ctx != NULL, -1);

    /* now we are ready to search for key */
    if((ctx->keyInfoReadCtx.keysMngr != NULL) && (ctx->keyInfoReadCtx.keysMngr->getKey != NULL)) {
        /* todo: set parameters to locate but not validate the key */
        key = (ctx->keyInfoReadCtx.keysMngr->getKey)(ctx->keyInfoNode, &(ctx->keyInfoReadCtx));
    }

    /* check that we got what we needed */
    if((key == NULL) || (!xmlSecKeyMatch(key, NULL, &(ctx->keyInfoReadCtx.keyReq)))) {
        if(key != NULL) {
            xmlSecKeyDestroy(key);
        }
        xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorNoMatch);
        return(-1);
    }

    xmlSecAssert2(key != NULL, -1);
    ret = xmlSecPtrListAdd(&(ctx->keys), key);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecPtrListAdd",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        xmlSecKeyDestroy(key);
        return(-1);
    }

    return(0);
}


/********************************************************************
 *
 * ValidateRequest/ValidateResponse
 *
 *******************************************************************/
static int              xmlSecXkmsServerRequestValidateNodeRead (xmlSecXkmsServerRequestId id,
                                                                 xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static int              xmlSecXkmsServerRequestValidateNodeWrite(xmlSecXkmsServerRequestId id,
                                                                 xmlSecXkmsServerCtxPtr ctx,
                                                                 xmlNodePtr node);
static int              xmlSecXkmsServerRequestValidateExecute  (xmlSecXkmsServerRequestId id,
                                                                 xmlSecXkmsServerCtxPtr ctx);

static xmlSecXkmsServerRequestKlass xmlSecXkmsServerRequestValidateKlass = {
    xmlSecXkmsServerRequestValidateName,        /* const xmlChar* name; */
    xmlSecNodeValidateRequest,                  /* const xmlChar* requestNodeName; */
    xmlSecXkmsNs,                               /* const xmlChar* requestNodeNs; */
    xmlSecNodeValidateResult,                   /* const xmlChar* responseNodeName; */
    xmlSecXkmsNs,                               /* const xmlChar* responseNodeNs; */
    XMLSEC_XKMS_SERVER_REQUEST_KLASS_ALLOWED_IN_COUMPOUND,      /* xmlSecBitMask flags; */
    xmlSecXkmsServerRequestValidateNodeRead,    /* xmlSecXkmsServerRequestNodeReadMethod readNode; */
    xmlSecXkmsServerRequestValidateNodeWrite,   /* xmlSecXkmsServerRequestNodeWriteMethod writeNode; */
    xmlSecXkmsServerRequestValidateExecute,     /* xmlSecXkmsServerRequestExecuteMethod execute; */
    NULL,                                       /* void* reserved1; */
    NULL                                        /* void* reserved2; */
};

/**
 * xmlSecXkmsServerRequestValidateGetKlass:
 *
 * The ValidateRequest klass.
 *
 * Returns: ValidateRequest klass.
 */
xmlSecXkmsServerRequestId
xmlSecXkmsServerRequestValidateGetKlass(void) {
    return(&xmlSecXkmsServerRequestValidateKlass);
}

/**
 *  <xkms:ValidateRequest Id Service Nonce? OriginalRequestId? ResponseLimit?>
 *      <ds:Signature>?
 *      <xkms:MessageExtension>*
 *      (<xkms:OpaqueClientData>
 *          <xkms:OpaqueData>?
 *      )?
 *      <xkms:ResponseMechanism>*
 *      <xkms:RespondWith>*
 *      <xkms:PendingNotification Mechanism Identifier>?
 *      <xkms:QueryKeyBinding Id?>
 *          <ds:KeyInfo>?
 *          <xkms:KeyUsage>?
 *          <xkms:KeyUsage>?
 *          <xkms:KeyUsage>?
 *          <xkms:UseKeyWith Application Identifier>*
 *          <xkms:TimeInstant Time>?
 *
 * XML Schema:
 *
 *    <!-- ValidateRequest -->
 *    <element name="ValidateRequest" type="xkms:ValidateRequestType"/>
 *    <complexType name="ValidateRequestType">
 *        <complexContent>
 *            <extension base="xkms:RequestAbstractType">
 *                <sequence>
 *                    <element ref="xkms:QueryKeyBinding"/>
 *                </sequence>
 *            </extension>
 *        </complexContent>
 *    </complexType>
 *    <!-- /ValidateRequest -->
 */
static int
xmlSecXkmsServerRequestValidateNodeRead(xmlSecXkmsServerRequestId id, xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(id == xmlSecXkmsServerRequestValidateId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = node;

    /* first read "parent" type */
    ret = xmlSecXkmsServerCtxRequestAbstractTypeNodeRead(ctx, &cur);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxRequestAbstractTypeNodeRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* now read required <xkms:QueryKeyBinding/> node */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeQueryKeyBinding, xmlSecXkmsNs))) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
                    XMLSEC_ERRORS_R_INVALID_NODE,
                    "node=%s",
                    xmlSecErrorsSafeString(xmlSecNodeQueryKeyBinding));
        return(-1);
    }

    /* read <xkms:QueryKeyBinding/> node */
    ret = xmlSecXkmsServerCtxQueryKeyBindingNodeRead(ctx, cur);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxQueryKeyBindingNodeRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* check that there is nothing after the last node */
    if(cur != NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
                    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

/**
 *  <xkms:ValidateResult Id Service Nonce? ResultMajor ResultMinor? RequestId?>
 *      <ds:Signature>?
 *      <xkms:MessageExtension>*
 *      (<xkms:OpaqueClientData>
 *           <xkms:OpaqueData>?
 *      )?
 *      <xkms:RequestSignatureValue>*
 *      (<xkms:KeyBinding Id?>
 *          <ds:KeyInfo>?
 *          <xkms:KeyUsage>?
 *          <xkms:KeyUsage>?
 *          <xkms:KeyUsage>?
 *          <xkms:UseKeyWith Application Identifier>*
 *          <xkms:ValidityInterval NotBefore NotOnOrAfter>?
 *          <xkms:Status StatusValue>
 *              (<xkms:ValidReason>?
 *               <xkms:IndeterminateReason>?
 *               <xkms:InvalidReason>?
 *              )*
 *      )*
 *
 * XML Schema:
 *
 *    <!-- ValidateResult -->
 *    <element name="ValidateResult" type="xkms:ValidateResultType"/>
 *    <complexType name="ValidateResultType">
 *        <complexContent>
 *            <extension base="xkms:ResultType">
 *                <sequence>
 *                    <element ref="xkms:KeyBinding" minOccurs="0"
 *                                  maxOccurs="unbounded"/>
 *                </sequence>
 *            </extension>
 *        </complexContent>
 *    </complexType>
 *    <!-- /ValidateResult -->
 */
static int
xmlSecXkmsServerRequestValidateNodeWrite(xmlSecXkmsServerRequestId id, xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlSecSize pos, size;
    xmlSecKeyPtr key;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(id == xmlSecXkmsServerRequestValidateId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first write the "parent" type */
    ret = xmlSecXkmsServerCtxResultTypeNodeWrite(ctx, node);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXkmsServerCtxResultTypeNodeWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* write keys in <xkms:UnverifiedKeyBinding> nodes */
    size = xmlSecPtrListGetSize(&(ctx->keys));
    for(pos = 0; pos < size; ++pos) {
        key = (xmlSecKeyPtr)xmlSecPtrListGetItem(&(ctx->keys), pos);
        if(key == NULL) {
            continue;
        }

        cur = xmlSecAddChild(node, xmlSecNodeUnverifiedKeyBinding, xmlSecXkmsNs);
        if(cur == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecAddChild",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "node=%s",
                        xmlSecErrorsSafeString(xmlSecNodeUnverifiedKeyBinding));
            return(-1);
        }

        ret = xmlSecXkmsServerCtxKeyBindingNodeWrite(ctx, cur, key);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecXkmsServerCtxKeyBindingNodeWrite",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    }

    return(0);
}

static int
xmlSecXkmsServerRequestValidateExecute(xmlSecXkmsServerRequestId id, xmlSecXkmsServerCtxPtr ctx) {
    xmlSecKeyPtr key = NULL;
    int ret;

    xmlSecAssert2(id == xmlSecXkmsServerRequestValidateId, -1);
    xmlSecAssert2(ctx != NULL, -1);

    /* now we are ready to search for key */
    if((ctx->keyInfoReadCtx.keysMngr != NULL) && (ctx->keyInfoReadCtx.keysMngr->getKey != NULL)) {
        key = (ctx->keyInfoReadCtx.keysMngr->getKey)(ctx->keyInfoNode, &(ctx->keyInfoReadCtx));
    }

    /* check that we got what we needed */
    if((key == NULL) || (!xmlSecKeyMatch(key, NULL, &(ctx->keyInfoReadCtx.keyReq)))) {
        if(key != NULL) {
            xmlSecKeyDestroy(key);
        }
        xmlSecXkmsServerCtxSetResult(ctx, xmlSecXkmsResultMajorSender, xmlSecXkmsResultMinorNoMatch);
        return(-1);
    }

    xmlSecAssert2(key != NULL, -1);
    ret = xmlSecPtrListAdd(&(ctx->keys), key);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecPtrListAdd",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        xmlSecKeyDestroy(key);
        return(-1);
    }

    return(0);
}

#endif /* XMLSEC_NO_XKMS */

