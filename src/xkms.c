/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * "XML Key Management Specification v 2.0" implementation
 *  http://www.w3.org/TR/xkms2/
 *
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
 *  <xkms:ResultType Id Service Nonce? ResultMajor ResultMinor? RequestId?>
 *      <ds:Signature>?
 *      <xkms:MessageExtension>*
 *      (<xkms:OpaqueClientData>
 *          <xkms:OpaqueData>?
 *      )?
 *      <xkms:RequestSignatureValue>*
 *       
 *  <xkms:KeyBindingAbstractType Id?>
 *      <ds:KeyInfo>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:UseKeyWith Application Identifier>*    
 *  
 *  <xkms:UnverifiedKeyBindingType Id?>
 *      <ds:KeyInfo>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:UseKeyWith Application Identifier>*    
 *      <xkms:ValidityInterval NotBefore NotOnOrAfter>?
 *  
 *  <xkms:KeyBindingType Id?>
 *      <ds:KeyInfo>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:UseKeyWith Application Identifier>*    
 *      <xkms:ValidityInterval NotBefore NotOnOrAfter>?
 *      <xkms:Status StatusValue>
 *      <xkms:ValidReason>*
 *      <xkms:IndeterminateReason>*
 *      <xkms:InvalidReason>*
 *       
 *  <xkms:QueryKeyBindingType Id?
 *      <ds:KeyInfo>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:KeyUsage>?
 *      <xkms:UseKeyWith Application Identifier>*    
 *      <xkms:TimeInstant Time>?
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
 *  <xkms:StatusResult Id Service Nonce? ResultMajor ResultMinor? RequestId? Success? Failure? Pending?>
 *      <ds:Signature>?
 *      <xkms:MessageExtension>*
 *      (<xkms:OpaqueClientData>
 *          <xkms:OpaqueData>?
 *      )?
 *      <xkms:RequestSignatureValue>*
 *  
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
 *  <xkms:ValidateResult Id Service Nonce? ResultMajor ResultMinor? RequestId?>
 *      <ds:Signature>?
 *      <xkms:MessageExtension>*
 *      (<xkms:OpaqueClientData>
 *           <xkms:OpaqueData>?
 *      )?
 *      <xkms:RequestSignatureValue>*
 *      (<xkms:KeyBindingType Id?>
 *          <ds:KeyInfo>?
 *          <xkms:KeyUsage>?
 *          <xkms:KeyUsage>?
 *          <xkms:KeyUsage>?
 *          <xkms:UseKeyWith Application Identifier>*    
 *          <xkms:ValidityInterval NotBefore NotOnOrAfter>?
 *          <xkms:Status StatusValue>
 *          <xkms:ValidReason>*
 *          <xkms:IndeterminateReason>*
 *          <xkms:InvalidReason>*
 *      )*
 *  
 *  
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
#include <xmlsec/xkms.h>
#include <xmlsec/errors.h>



/**************************************************************************
 *
 * 
 *
 *************************************************************************/
/* The ID attribute in XKMS is 'Id' */
static const xmlChar* xmlSecXkmsServerIds[] = { BAD_CAST "Id", NULL };

static int	xmlSecXkmsServerCtxLocateRequestNodeRead	(xmlSecXkmsServerCtxPtr ctx,
							         xmlNodePtr node);
static int	xmlSecXkmsServerCtxRequestAbstractTypeNodeRead	(xmlSecXkmsServerCtxPtr ctx,
							         xmlNodePtr* node);
static int	xmlSecXkmsServerCtxSignatureNodeRead		(xmlSecXkmsServerCtxPtr ctx, 
								 xmlNodePtr node);
static int	xmlSecXkmsServerCtxMessageExtensionNodesRead	(xmlSecXkmsServerCtxPtr ctx, 
								 xmlNodePtr* node);
static int	xmlSecXkmsServerCtxOpaqueClientDataNodeRead	(xmlSecXkmsServerCtxPtr ctx, 
								 xmlNodePtr node);
static int	xmlSecXkmsServerCtxPendingNotificationNodeRead	(xmlSecXkmsServerCtxPtr ctx, 
								 xmlNodePtr node);
static int	xmlSecXkmsServerCtxRespondWithNodesRead		(xmlSecXkmsServerCtxPtr ctx, 
								 xmlNodePtr* node);
static int	xmlSecXkmsServerCtxQueryKeyBindingNodeRead	(xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
static int	xmlSecXkmsServerCtxKeyBindingAbstractTypeNodeRead(xmlSecXkmsServerCtxPtr ctx,
							         xmlNodePtr* node);
static int	xmlSecXkmsServerCtxKeyBindingAbstractTypeNodeWrite(xmlSecXkmsServerCtxPtr ctx,
							         xmlNodePtr node,
								 xmlSecKeyPtr key);
static int	xmlSecXkmsServerCtxKeyInfoNodeWrite		(xmlSecXkmsServerCtxPtr ctx,
							    	 xmlNodePtr node,
								 xmlSecKeyPtr key);
static int	xmlSecXkmsServerCtxUseKeyWithNodesRead		(xmlSecXkmsServerCtxPtr ctx, 
								 xmlNodePtr* node);
static int	xmlSecXkmsServerCtxUseKeyWithNodesWrite		(xmlSecXkmsServerCtxPtr ctx, 
								 xmlNodePtr node,
								 xmlSecKeyPtr key);
static int	xmlSecXkmsServerCtxTimeInstantNodeRead		(xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
static int	xmlSecXkmsServerCtxResultTypeNodeWrite		(xmlSecXkmsServerCtxPtr ctx, 
								 xmlNodePtr node);
static int	xmlSecXkmsServerCtxRequestSignatureValueNodeWrite(xmlSecXkmsServerCtxPtr ctx, 
								 xmlNodePtr node);
static int	xmlSecXkmsServerCtxLocateResultNodeWrite	(xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
static int	xmlSecXkmsServerCtxUnverifiedKeyBindingNodeWrite(xmlSecXkmsServerCtxPtr ctx,
							    	 xmlNodePtr node,
								 xmlSecKeyPtr key);
static int 	xmlSecXkmsServerCtxValidityIntervalNodeWrite	(xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node, 
								 xmlSecKeyPtr key);


static const xmlSecString2IntegerInfo gXmlSecXkmsMajorErrorInfo[] = 
{
    { xmlSecResultMajorCodeSuccess,
      XMLSEC_XKMS_ERROR_MAJOR_SUCCESS },
    { xmlSecResultMajorCodeVersionMismatch,
      XMLSEC_XKMS_ERROR_MAJOR_VERSION_MISMATCH },
    { xmlSecResultMajorCodeSender,
      XMLSEC_XKMS_ERROR_MAJOR_SENDER },
    { xmlSecResultMajorCodeReceiver,
      XMLSEC_XKMS_ERROR_MAJOR_RECEIVER },
    { xmlSecResultMajorCodeRepresent,
      XMLSEC_XKMS_ERROR_MAJOR_REPRESENT },
    { xmlSecResultMajorCodePending,
      XMLSEC_XKMS_ERROR_MAJOR_PENDING },
    { NULL, 
      0 }	/* MUST be last in the list */
};

static const xmlSecString2IntegerInfo gXmlSecXkmsMinorErrorInfo[] = 
{
    { xmlSecResultMinorCodeNoMatch,
      XMLSEC_XKMS_ERROR_MINOR_NO_MATCH },
    { xmlSecResultMinorCodeTooManyResponses,
      XMLSEC_XKMS_ERROR_MINOR_TOO_MANY_RESPONSES },
    { xmlSecResultMinorCodeIncomplete,
      XMLSEC_XKMS_ERROR_MINOR_INCOMPLETE },
    { xmlSecResultMinorCodeFailure,
      XMLSEC_XKMS_ERROR_MINOR_FAILURE },
    { xmlSecResultMinorCodeRefused,
      XMLSEC_XKMS_ERROR_MINOR_REFUSED },
    { xmlSecResultMinorCodeNoAuthentication,
      XMLSEC_XKMS_ERROR_MINOR_NO_AUTHENTICATION },
    { xmlSecResultMinorCodeMessageNotSupported,
      XMLSEC_XKMS_ERROR_MINOR_MESSAGE_NOT_SUPPORTED },
    { xmlSecResultMinorCodeUnknownResponseId,
      XMLSEC_XKMS_ERROR_MINOR_UNKNOWN_RESPONSE_ID },
    { xmlSecResultMinorCodeNotSynchronous,
      XMLSEC_XKMS_ERROR_MINOR_NOT_SYNCHRONOUS },
    { NULL, 
      0 }	/* MUST be last in the list */
};

static const xmlSecString2BitMaskInfo gXmlSecXkmsResponseMechanismInfo[] = 
{
    { xmlSecResponseMechanismRepresent,
      XMLSEC_XKMS_RESPONSE_MECHANISM_MASK_REPRESENT },
    { xmlSecResponseMechanismPending,
      XMLSEC_XKMS_RESPONSE_MECHANISM_MASK_PENDING },
    { xmlSecResponseMechanismRequestSignatureValue,
      XMLSEC_XKMS_RESPONSE_MECHANISM_MASK_REQUEST_SIGNATURE_VALUE },
    { NULL, 
      0 }	/* MUST be last in the list */
};

static const xmlSecString2BitMaskInfo gXmlSecXkmsKeyUsageInfo[] = 
{
    { xmlSecKeyUsageEncryption,
      xmlSecKeyUsageEncrypt | xmlSecKeyUsageDecrypt },
    { xmlSecKeyUsageSignature,
      xmlSecKeyUsageSign | xmlSecKeyUsageVerify },
    { xmlSecKeyUsageExchange,
      xmlSecKeyUsageKeyExchange},
    { NULL, 
      0 }	/* MUST be last in the list */
};

/**
 * xmlSecXkmsServerCtxCreate:
 * @keysMngr: 		the pointer to keys manager.
 *
 * Creates XKMS request server side processing context.
 * The caller is responsible for destroying returend object by calling 
 * #xmlSecXkmsServerCtxDestroy function.
 *
 * Returns pointer to newly allocated context object or NULL if an error
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
 * @ctx:		the pointer to XKMS processing context.
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
 * @ctx:		the pointer to XKMS processing context.
 * @keysMngr: 		the pointer to keys manager.
 *
 * Initializes XKMS element processing context.
 * The caller is responsible for cleaing up returend object by calling 
 * #xmlSecXkmsServerCtxFinalize function.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkmsServerCtxInitialize(xmlSecXkmsServerCtxPtr ctx, xmlSecKeysMngrPtr keysMngr) {
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    
    memset(ctx, 0, sizeof(xmlSecXkmsServerCtx));

    ctx->majorError 	= XMLSEC_XKMS_ERROR_MAJOR_SUCCESS;
    ctx->minorError 	= XMLSEC_XKMS_ERROR_MINOR_NONE;
    ctx->responseLimit  = XMLSEC_XKMS_NO_RESPONSE_LIMIT;

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
    ret = xmlSecPtrListInitialize(&(ctx->enabledRespondWith), xmlSecXkmsRespondWithIdListId);
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
 * @ctx:		the pointer to XKMS processing context.
 *
 * Cleans up @ctx object.
 */
void 
xmlSecXkmsServerCtxFinalize(xmlSecXkmsServerCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    xmlSecXkmsServerCtxReset(ctx);
    
    xmlSecKeyInfoCtxFinalize(&(ctx->keyInfoReadCtx));
    xmlSecKeyInfoCtxFinalize(&(ctx->keyInfoWriteCtx));
    xmlSecPtrListFinalize(&(ctx->enabledRespondWith));
    xmlSecPtrListFinalize(&(ctx->keys));
    xmlSecPtrListFinalize(&(ctx->respWithList));
    memset(ctx, 0, sizeof(xmlSecXkmsServerCtx));
}

/**
 * xmlSecXkmsServerCtxReset:
 * @ctx:		the pointer to XKMS processing context.
 *
 * Resets @ctx object, user settings are not touched.
 */
void 
xmlSecXkmsServerCtxReset(xmlSecXkmsServerCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);
    
    ctx->majorError = XMLSEC_XKMS_ERROR_MAJOR_SUCCESS;
    ctx->minorError = XMLSEC_XKMS_ERROR_MINOR_NONE;
    xmlSecKeyInfoCtxReset(&(ctx->keyInfoReadCtx));
    xmlSecKeyInfoCtxReset(&(ctx->keyInfoWriteCtx));
    xmlSecPtrListEmpty(&(ctx->keys));
    xmlSecPtrListEmpty(&(ctx->respWithList));

    ctx->opaqueClientDataNode   = NULL;    
    ctx->firtsMsgExtNode 	= NULL;
    ctx->keyInfoNode		= NULL;
    
    if(ctx->requestId != NULL) {
	xmlFree(ctx->requestId); ctx->requestId = NULL;
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
    ctx->responseLimit 		= XMLSEC_XKMS_NO_RESPONSE_LIMIT;
    ctx->responseMechanismMask  = 0;

    if(ctx->result != NULL) {
	xmlFreeDoc(ctx->result);
	ctx->result = NULL;
    }
}

/**
 * xmlSecXkmsServerCtxCopyUserPref:
 * @dst:		the pointer to destination context.
 * @src:		the pointer to source context.
 * 
 * Copies user preference from @src context to @dst.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkmsServerCtxCopyUserPref(xmlSecXkmsServerCtxPtr dst, xmlSecXkmsServerCtxPtr src) {
    int ret;
    
    xmlSecAssert2(dst != NULL, -1);
    xmlSecAssert2(src != NULL, -1);

    dst->userData 	= src->userData;
    dst->flags		= src->flags;
    dst->flags2		= src->flags2;
    dst->mode 		= src->mode;

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

    ret = xmlSecPtrListCopy(&(dst->enabledRespondWith), &(src->enabledRespondWith));
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
 * xmlSecXkmsServerCtxSetError: 
 * @ctx:	the pointer to XKMS processing context.
 * @majorError:	the major error code.
 * @minorError: the minor error code.
 * 
 * Sets the major/minor error code in the context if no other error is already
 * reported.
 */
void 
xmlSecXkmsServerCtxSetError(xmlSecXkmsServerCtxPtr ctx, int majorError, int minorError) {
    xmlSecAssert(ctx != NULL);
    
    if((ctx->majorError == XMLSEC_XKMS_ERROR_MAJOR_SUCCESS) && (minorError != XMLSEC_XKMS_ERROR_MAJOR_SUCCESS)) {
	ctx->majorError = majorError;
	ctx->minorError = minorError;
    } else if((ctx->majorError == XMLSEC_XKMS_ERROR_MAJOR_SUCCESS) && (ctx->minorError == XMLSEC_XKMS_ERROR_MINOR_NONE)) {
	xmlSecAssert(majorError == XMLSEC_XKMS_ERROR_MAJOR_SUCCESS);
	
	ctx->minorError = minorError;
    }
}

/**
 * xmlSecXkmsServerCtxLocate:
 * @ctx:	the pointer to XKMS processing context.
 * @node:		the pointer to <xkms:LocateRequest/> node.
 *
 * Process "locate key data" request from @node and returns key data 
 * in the #result member of the @ctx structure.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkmsServerCtxLocate(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlSecKeyPtr key = NULL;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->result == NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    xmlSecAddIDs(node->doc, node, xmlSecXkmsServerIds);
    ret = xmlSecXkmsServerCtxLocateRequestNodeRead(ctx, node);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsServerCtxLocateRequestNodeRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecXkmsServerCtxSetError(ctx, XMLSEC_XKMS_ERROR_MAJOR_SENDER, XMLSEC_XKMS_ERROR_MINOR_FAILURE);
	goto done;
    }

    /* now we are ready to search for key */
    if((ctx->keyInfoReadCtx.keysMngr != NULL) && (ctx->keyInfoReadCtx.keysMngr->getKey != NULL)) {
	key = (ctx->keyInfoReadCtx.keysMngr->getKey)(ctx->keyInfoNode, &(ctx->keyInfoReadCtx));
    }
    
    /* check that we got what we needed */
    if((key == NULL) || (!xmlSecKeyMatch(key, NULL, &(ctx->keyInfoReadCtx.keyReq)))) {
	if(key != NULL) {
    	    xmlSecKeyDestroy(key);
	}
	xmlSecXkmsServerCtxSetError(ctx, XMLSEC_XKMS_ERROR_MAJOR_SENDER, XMLSEC_XKMS_ERROR_MINOR_NO_MATCH);
	goto done;
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
	xmlSecXkmsServerCtxSetError(ctx, XMLSEC_XKMS_ERROR_MAJOR_RECEIVER, XMLSEC_XKMS_ERROR_MINOR_FAILURE);
	goto done;
    }

done:
    /* create the response document */
    xmlSecAssert2(ctx->result == NULL, -1);
    ctx->result = xmlSecCreateTree(xmlSecNodeLocateResult, xmlSecXkmsNs);
    if(ctx->result == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCreateTree",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	/* this is really, really bad error... we could do nothing */
	return(-1);
    }
    
    /* and write back the response */
    xmlSecAssert2(ctx->result != NULL, -1);
    ret = xmlSecXkmsServerCtxLocateResultNodeWrite(ctx, xmlDocGetRootElement(ctx->result)); 
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsServerCtxLocateResultNodeWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	/* this is really, really bad error... we could do nothing */
	return(-1);
    }

    return(0);
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
xmlSecXkmsServerCtxLocateRequestNodeRead(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->mode == xmlXkmsServerCtxModeLocateRequest, -1);
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
    xmlSecAssert2(ctx->requestId == NULL, -1);
    ctx->requestId = xmlGetProp(cur, xmlSecAttrId);
    if(ctx->requestId == NULL) {
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
    /* todo: check service? */

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
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeSignature, xmlSecDSigNs))) {
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
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeOpaqueClientData, xmlSecXkmsNs))) {
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
    ret = xmlSecString2BitMaskNodesRead(gXmlSecXkmsResponseMechanismInfo, &cur, 
			xmlSecNodeResponseMechanism, xmlSecXkmsNs, 
			&ctx->responseMechanismMask);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecString2BitMaskNodesRead",
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
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodePendingNotification, xmlSecXkmsNs))) {
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
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeMessageExtension, xmlSecXkmsNs))) {
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
    xmlChar* content;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->mode == xmlXkmsServerCtxModeLocateRequest, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = (*node);
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeRespondWith, xmlSecXkmsNs))) {
	content = xmlNodeGetContent(cur);
	if(content != NULL) {
	    xmlSecXkmsRespondWithId id = xmlSecXkmsRespondWithIdUnknown;

	    /* todo: trim content? */
	    if(xmlSecPtrListGetSize(&(ctx->enabledRespondWith)) > 0) {
		id = xmlSecXkmsRespondWithIdListFindByName(&(ctx->enabledRespondWith), content);
	    } else {
		id = xmlSecXkmsRespondWithIdListFindByName(xmlSecXkmsRespondWithIdsGet(), content);	
	    }
	    xmlFree(content);

	    if(id != xmlSecXkmsRespondWithIdUnknown) {	
		ret = xmlSecXkmsRespondWithReadNode(id, ctx, cur);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
			        NULL,
				"xmlSecCreateTree",
			        XMLSEC_ERRORS_R_XMLSEC_FAILED,
				XMLSEC_ERRORS_NO_MESSAGE);
		    return(-1);
		}
	    } else if(0) {
/*
		TODO: add a flag to skip this error
    		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    NULL,
			    XMLSEC_ERRORS_R_,
			    "name=%s",
			    xmlSecErrorsSafeString(content));
*/
		return(-1);
	    }
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
 *      <xkms:QueryKeyBinding Id?>
 *          <ds:KeyInfo>?
 *          <xkms:KeyUsage>?
 *          <xkms:KeyUsage>?
 *          <xkms:KeyUsage>?
 *          <xkms:UseKeyWith Application Identifier>*    
 *          <xkms:TimeInstant Time>?
 *
 * XML Schema:
 *   <!-- QueryKeyBinding -->
 *   <element name="QueryKeyBinding" type="xkms:QueryKeyBindingType"/>
 *   <complexType name="QueryKeyBindingType">
 *      <complexContent>
 *          <extension base="xkms:KeyBindingAbstractType">
 *	        <sequence>
 *		    <element ref="xkms:TimeInstant" minOccurs="0"/>
 *		</sequence>
 *	    </extension>
 *	</complexContent>
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
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeTimeInstant, xmlSecXkmsNs))) {
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
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeKeyInfo, xmlSecDSigNs))) {
	ctx->keyInfoNode = cur;
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* next is zero or more <xkms:KeyUsage/> nodes */
    ret = xmlSecString2BitMaskNodesRead(gXmlSecXkmsKeyUsageInfo, &cur,
		    xmlSecNodeKeyUsage, xmlSecXkmsNs, 
		    &(ctx->keyInfoReadCtx.keyReq.keyUsage));
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecString2BitMaskNodesRead",
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

    /* todo: generate and add Id attribute */

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
    ret = xmlSecString2BitMaskNodesWrite(gXmlSecXkmsKeyUsageInfo, node,
		    xmlSecNodeKeyUsage, xmlSecXkmsNs, 
		    key->usage);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecString2BitMaskNodesWrite",
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
    xmlSecAssert2(ctx->mode == xmlXkmsServerCtxModeLocateRequest, -1);
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
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeUseKeyWith, xmlSecXkmsNs))) {
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

    /* todo: */
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
 *	       </sequence>
 *	       <attribute name="ResultMajor" type="QName" use="required"/>
 *	       <attribute name="ResultMinor" type="QName" use="optional"/>
 *	       <attribute name="RequestId" type="anyURI" use="optional"/>
 *	    </extension>
 *	 </complexContent>
 *    </complexType>
 *    <!-- /ResultType -->
 */
static int 
xmlSecXkmsServerCtxResultTypeNodeWrite(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* todo: generate and write Id attribute */
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
    if((ctx->requestId != NULL) && (xmlSetProp(node, xmlSecAttrRequestId, ctx->requestId) == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSetProp",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "name=%s,value=%s",
		    xmlSecErrorsSafeString(xmlSecAttrRequestId),
		    xmlSecErrorsSafeString(ctx->requestId));
	return(-1);	
    }
    
    
    /* set major code (required) */ 
    ret = xmlSecString2IntegerAttributeWrite(gXmlSecXkmsMajorErrorInfo, node,
					     xmlSecAttrResultMajor, ctx->majorError);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecString2IntegerAttributeWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=%s,value=%d",
		    xmlSecErrorsSafeString(xmlSecAttrResultMajor),
		    ctx->majorError);
	return(-1);	
    }

    /* set minor code (optional) */ 
    if(ctx->minorError != XMLSEC_XKMS_ERROR_MINOR_NONE) {
        ret = xmlSecString2IntegerAttributeWrite(gXmlSecXkmsMinorErrorInfo, node,
					     xmlSecAttrResultMinor, ctx->minorError);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        NULL,
			"xmlSecString2IntegerAttributeWrite",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
		        "name=%s,value=%d",
			xmlSecErrorsSafeString(xmlSecAttrResultMinor),
			ctx->minorError);
	    return(-1);	
	}
    }

    /* todo: create signature template */
    
    /* todo: create message extension nodes? */

    /* <xkms:OpaqueClientData/>: An XKMS service SHOULD return the value of 
     * the <OpaqueClientData> element unmodified in a request in a response 
     * with status code Succes */
    if((ctx->majorError == XMLSEC_XKMS_ERROR_MAJOR_SUCCESS) && (ctx->opaqueClientDataNode != NULL)) {
        xmlNodePtr copyNode;

	copyNode = xmlDocCopyNode(ctx->opaqueClientDataNode, ctx->result, 1);
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
    
    /* todo: check all conditions */
    if((ctx->responseMechanismMask & XMLSEC_XKMS_RESPONSE_MECHANISM_MASK_REQUEST_SIGNATURE_VALUE) == 0) {
	/* The ResponseMechanism RequestSignatureValue was not specified. */
	return(0);
    }
    
    /* todo: write RequestSignatureValue */
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
 *	        <extension base="xkms:ResultType">
 *		     <sequence>
 *		         <element ref="xkms:UnverifiedKeyBinding" minOccurs="0" 
 *			          maxOccurs="unbounded"/>
 *		     </sequence>
 *		</extension>
 *	   </complexContent>
 *    </complexType>
 *    <!-- /LocateResult -->
 */ 
static int
xmlSecXkmsServerCtxLocateResultNodeWrite(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlSecSize pos, size;
    xmlSecKeyPtr key;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->mode == xmlXkmsServerCtxModeLocateRequest, -1);
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

/** 
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
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    /* todo: */
    return(0);
}

/**
 * xmlSecXkmsServerCtxValidate:
 * @ctx:		the pointer to XKMS processing context.
 * @node:		the pointer to <xkms:ValidateRequest/> node.
 *
 * Process "locate and validate key data" request from @node and returns key data 
 * in the #result member of the @ctx structure.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkmsServerCtxValidate(xmlSecXkmsServerCtxPtr ctx, xmlNodePtr node) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    ctx->mode = xmlXkmsServerCtxModeValidateRequest;
    
    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecXkmsServerCtxLocate",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

/**
 * xmlSecXkmsServerCtxDebugDump:
 * @ctx:		the pointer to XKMS processing context.
 * @output:		the pointer to output FILE.
 *
 * Prints the debug information about @ctx to @output.
 */
void 
xmlSecXkmsServerCtxDebugDump(xmlSecXkmsServerCtxPtr ctx, FILE* output) {
    xmlSecAssert(ctx != NULL);
    xmlSecAssert(output != NULL);
    
    switch(ctx->mode) {
	case xmlXkmsServerCtxModeLocateRequest:
	    fprintf(output, "= XKMS SERVER LOCATE REQUEST CONTEXT\n");
	    break;
	case xmlXkmsServerCtxModeValidateRequest:
	    fprintf(output, "= XKMS SERVER VALIDATE REQUEST CONTEXT\n");
	    break;
    }

    xmlSecString2IntegerDebugDump(gXmlSecXkmsMajorErrorInfo, 
		ctx->majorError, BAD_CAST "majorError", output);    
    xmlSecString2IntegerDebugDump(gXmlSecXkmsMinorErrorInfo, 
		ctx->minorError, BAD_CAST "minorError", output);    

    fprintf(output, "== requestId: %s\n", 
		(ctx->requestId) ? ctx->requestId : BAD_CAST "");
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
    xmlSecString2BitMaskDebugDump(gXmlSecXkmsResponseMechanismInfo, 
		ctx->responseMechanismMask, BAD_CAST "responseMechanism", output);    
    
    fprintf(output, "== flags: 0x%08x\n", ctx->flags);
    fprintf(output, "== flags2: 0x%08x\n", ctx->flags2);

    fprintf(output, "== Key Info Read Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(ctx->keyInfoReadCtx), output);
    
    fprintf(output, "== Key Info Write Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(ctx->keyInfoWriteCtx), output);

    if(xmlSecPtrListGetSize(&(ctx->enabledRespondWith)) > 0) {
	fprintf(output, "== Enabled RespondWith: ");
	xmlSecTransformIdListDebugDump(&(ctx->enabledRespondWith), output);
    } else {
	fprintf(output, "== Enabled RespondWith: all\n");
    }

    fprintf(output, "== RespondWith List:\n");
    xmlSecPtrListDebugDump(&(ctx->respWithList), output);

    fprintf(output, "== Keys:\n");
    xmlSecPtrListDebugDump(&(ctx->keys), output);

}

/**
 * xmlSecXkmsServerCtxDebugXmlDump:
 * @ctx:		the pointer to XKMS processing context.
 * @output:		the pointer to output FILE.
 *
 * Prints the debug information about @ctx to @output in XML format.
 */
void 
xmlSecXkmsServerCtxDebugXmlDump(xmlSecXkmsServerCtxPtr ctx, FILE* output) {
    xmlSecAssert(ctx != NULL);
    xmlSecAssert(output != NULL);

    switch(ctx->mode) {
	case xmlXkmsServerCtxModeLocateRequest:
	    fprintf(output, "<XkmsServerLocateRequestContext>\n");
	    break;
	case xmlXkmsServerCtxModeValidateRequest:
	    fprintf(output, "<XkmsServerValidateRequestContext>\n");
	    break;
    }

    xmlSecString2IntegerDebugXmlDump(gXmlSecXkmsMajorErrorInfo, 
		ctx->majorError, BAD_CAST "MajorError", output);    
    xmlSecString2IntegerDebugXmlDump(gXmlSecXkmsMinorErrorInfo, 
		ctx->minorError, BAD_CAST "MinorError", output);    

    fprintf(output, "<RequestId>%s</RequestId>\n", 
		(ctx->requestId) ? ctx->requestId : BAD_CAST "");
    fprintf(output, "<Service>%s</Service>\n", 
		(ctx->service) ? ctx->service : BAD_CAST "");
    fprintf(output, "<Nonce>%s</Nonce>\n", 
		(ctx->nonce) ? ctx->nonce : BAD_CAST "");
    fprintf(output, "<OriginalRequestId>%s</OriginalRequestId>\n", 
		(ctx->originalRequestId) ? ctx->originalRequestId : BAD_CAST "");
    fprintf(output, "<PendingNotificationMechanism>%s</PendingNotificationMechanism>\n", 
		(ctx->pendingNotificationMechanism) ? 
		    ctx->pendingNotificationMechanism : 
		    BAD_CAST "");
    fprintf(output, "<PendingNotificationIdentifier>%s</PendingNotificationIdentifier>\n", 
		(ctx->pendingNotificationIdentifier) ? 
		    ctx->pendingNotificationIdentifier : 
		    BAD_CAST "");
    if(ctx->responseLimit != XMLSEC_XKMS_NO_RESPONSE_LIMIT) {
        fprintf(output, "<ResponseLimit>%d</ResponseLimit>\n", ctx->responseLimit);
    }
    xmlSecString2BitMaskDebugXmlDump(gXmlSecXkmsResponseMechanismInfo, 
		ctx->responseMechanismMask, BAD_CAST "ResponseMechanism", output);    

    fprintf(output, "<Flags>%08x</Flags>\n", ctx->flags);
    fprintf(output, "<Flags2>%08x</Flags2>\n", ctx->flags2);

    fprintf(output, "<KeyInfoReadCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(ctx->keyInfoReadCtx), output);
    fprintf(output, "</KeyInfoReadCtx>\n");

    fprintf(output, "<KeyInfoWriteCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(ctx->keyInfoWriteCtx), output);
    fprintf(output, "</KeyInfoWriteCtx>\n");

    if(xmlSecPtrListGetSize(&(ctx->enabledRespondWith)) > 0) {
	fprintf(output, "<EnabledRespondWith>\n");
	xmlSecTransformIdListDebugXmlDump(&(ctx->enabledRespondWith), output);
	fprintf(output, "</EnabledRespondWith>\n");
    } else {
	fprintf(output, "<EnabledRespondWith>all</EnabledRespondWith>\n");
    }

    fprintf(output, "<RespondWithList>\n");
    xmlSecPtrListDebugXmlDump(&(ctx->respWithList), output);
    fprintf(output, "</RespondWithList>\n");

    fprintf(output, "<Keys>\n");
    xmlSecPtrListDebugXmlDump(&(ctx->keys), output);
    fprintf(output, "</Keys>\n");

    switch(ctx->mode) {
	case xmlXkmsServerCtxModeLocateRequest:
	    fprintf(output, "</XkmsServerLocateRequestContext>\n");
	    break;
	case xmlXkmsServerCtxModeValidateRequest:
	    fprintf(output, "</XkmsServerValidateRequestContext>\n");
	    break;
    }
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
 * Returns the pointer to list of all registered RespondWith klasses.
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
 * Returns 0 on success or a negative value if an error occurs.
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
 * @id:			the RespondWith klass.
 *
 * Registers @id in the global list of RespondWith klasses.
 *
 * Returns 0 on success or a negative value if an error occurs.
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
 * Returns 0 on success or a negative value if an error occurs.
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
 * xmlSecXkmsRespondWithReadNode:
 * @id:			the RespondWith class.
 * @ctx:	the XKMS request processing context.
 * @node:		the pointer to <xkms:RespondWith/> node.
 *
 * Reads the content of the <xkms:RespondWith/> @node.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int  
xmlSecXkmsRespondWithReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
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
 * xmlSecXkmsRespondWithWriteNode:
 * @id:			the RespondWith class.
 * @ctx:	the XKMS request processing context.
 * @node:		the pointer to <xkms:RespondWith/> node.
 *
 * Writes the content of the <xkms:RespondWith/> @node.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkmsRespondWithWriteNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
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
 * @id:			the RespondWith class.
 * @output:		the output file.
 *
 * Writes debug information about @id into the @output.
 */
void 
xmlSecXkmsRespondWithDebugDump(xmlSecXkmsRespondWithId id, FILE* output) {
    xmlSecAssert(id != xmlSecXkmsRespondWithIdUnknown);
    xmlSecAssert(output != NULL);

    fprintf(output, "=== RespondWith: %s\n", xmlSecErrorsSafeString(id->name));
}

/**
 * xmlSecXkmsRespondWithDebugXmlDump:
 * @id:			the RespondWith class.
 * @output:		the output file.
 *
 * Writes debug information about @id into the @output in XML format.
 */
void 
xmlSecXkmsRespondWithDebugXmlDump(xmlSecXkmsRespondWithId id, FILE* output) {
    xmlSecAssert(id != xmlSecXkmsRespondWithIdUnknown);
    xmlSecAssert(output != NULL);

    fprintf(output, "<RespondWith>%s</RespondWith>\n", xmlSecErrorsSafeString(id->name));
}

int 
xmlSecXkmsRespondWithDefaultReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
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
xmlSecXkmsRespondWithDefaultWriteNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
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
    NULL, 								/* xmlSecPtrDuplicateItemMethod duplicateItem; */
    NULL,								/* xmlSecPtrDestroyItemMethod destroyItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecXkmsRespondWithDebugDump,	/* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecXkmsRespondWithDebugXmlDump,	/* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
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
xmlSecXkmsRespondWithIdListFindByName(xmlSecPtrListPtr list, const xmlChar* name) {
    xmlSecXkmsRespondWithId id;
    xmlSecSize i, size;
    
    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecXkmsRespondWithIdListId), xmlSecXkmsRespondWithIdUnknown);
    xmlSecAssert2(name != NULL, xmlSecXkmsRespondWithIdUnknown);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
	id = (xmlSecXkmsRespondWithId)xmlSecPtrListGetItem(list, i);
	if((id !=  xmlSecXkmsRespondWithIdUnknown) && xmlStrEqual(id->name, name)) {
	    return(id);
	}
    }
    return(xmlSecXkmsRespondWithIdUnknown);    
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
	    ret = xmlSecXkmsRespondWithWriteNode(id, ctx, node);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
			    "xmlSecXkmsRespondWithWriteNode",
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
    xmlSecRespondWithKeyName,			/* const xmlChar* name; */
    xmlSecNodeKeyName,				/* const xmlChar* nodeName; */
    xmlSecDSigNs,				/* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithDefaultReadNode,	/* xmlSecXkmsRespondWithReadNodeMethod readNode; */
    xmlSecXkmsRespondWithDefaultWriteNode	/* xmlSecXkmsRespondWithWriteNodeMethod writeNode; */
};

/**
 * xmlSecXkmsRespondWithKeyNameGetKlass:
 *
 * The respond with KeyName klass.
 *
 * Returns respond with KeyName klass.
 */ 
xmlSecXkmsRespondWithId	
xmlSecXkmsRespondWithKeyNameGetKlass(void) {
    return(&xmlSecXkmsRespondWithKeyNameKlass);
}



static  int  		xmlSecXkmsRespondWithKeyValueReadNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithKeyValueKlass = {
    xmlSecRespondWithKeyValue,			/* const xmlChar* name; */
    xmlSecNodeKeyValue,				/* const xmlChar* nodeName; */
    xmlSecDSigNs,				/* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithKeyValueReadNode,	/* xmlSecXkmsRespondWithReadNodeMethod readNode; */
    xmlSecXkmsRespondWithDefaultWriteNode	/* xmlSecXkmsRespondWithWriteNodeMethod writeNode; */
};

/**
 * xmlSecXkmsRespondWithKeyValueGetKlass:
 *
 * The respond with KeyValue klass.
 *
 * Returns respond with KeyValue klass.
 */ 
xmlSecXkmsRespondWithId	
xmlSecXkmsRespondWithKeyValueGetKlass(void) {
    return(&xmlSecXkmsRespondWithKeyValueKlass);
}

static  int  
xmlSecXkmsRespondWithKeyValueReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithKeyValueId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, ctx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
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

static  int  		xmlSecXkmsRespondWithPrivateKeyReadNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithPrivateKeyKlass = {
    xmlSecRespondWithPrivateKey,		/* const xmlChar* name; */
    xmlSecNodeKeyValue,				/* const xmlChar* nodeName; */
    xmlSecDSigNs,				/* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithPrivateKeyReadNode,	/* xmlSecXkmsRespondWithReadNodeMethod readNode; */
    xmlSecXkmsRespondWithDefaultWriteNode	/* xmlSecXkmsRespondWithWriteNodeMethod writeNode; */
};

/**
 * xmlSecXkmsRespondWithPrivateKeyGetKlass:
 *
 * The respond with PrivateKey klass.
 *
 * Returns respond with PrivateKey klass.
 */ 
xmlSecXkmsRespondWithId	
xmlSecXkmsRespondWithPrivateKeyGetKlass(void) {
    return(&xmlSecXkmsRespondWithPrivateKeyKlass);
}

static  int  
xmlSecXkmsRespondWithPrivateKeyReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithPrivateKeyId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, ctx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
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
    xmlSecRespondWithRetrievalMethod,		/* const xmlChar* name; */
    xmlSecNodeRetrievalMethod,			/* const xmlChar* nodeName; */
    xmlSecDSigNs,				/* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithDefaultReadNode,	/* xmlSecXkmsRespondWithReadNodeMethod readNode; */
    xmlSecXkmsRespondWithDefaultWriteNode	/* xmlSecXkmsRespondWithWriteNodeMethod writeNode; */
};

/**
 * xmlSecXkmsRespondWithRetrievalMethodGetKlass:
 *
 * The respond with RetrievalMethod klass.
 *
 * Returns respond with RetrievalMethod klass.
 */ 
xmlSecXkmsRespondWithId	
xmlSecXkmsRespondWithRetrievalMethodGetKlass(void) {
    return(&xmlSecXkmsRespondWithRetrievalMethodKlass);
}



static  int  		xmlSecXkmsRespondWithX509CertReadNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithX509CertKlass = {
    xmlSecRespondWithX509Cert,			/* const xmlChar* name; */
    xmlSecNodeX509Data,				/* const xmlChar* nodeName; */
    xmlSecDSigNs,				/* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithX509CertReadNode,	/* xmlSecXkmsRespondWithReadNodeMethod readNode; */
    xmlSecXkmsRespondWithDefaultWriteNode	/* xmlSecXkmsRespondWithWriteNodeMethod writeNode; */
};

/**
 * xmlSecXkmsRespondWithX509CertGetKlass:
 *
 * The respond with X509Cert klass.
 *
 * Returns respond with X509Cert klass.
 */ 
xmlSecXkmsRespondWithId	
xmlSecXkmsRespondWithX509CertGetKlass(void) {
    return(&xmlSecXkmsRespondWithX509CertKlass);
}

static  int  
xmlSecXkmsRespondWithX509CertReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithX509CertId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, ctx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the ctx */

    /* todo 
    ctx->keyInfoWriteCtx;
    */
    return(0);
}

static  int  		xmlSecXkmsRespondWithX509ChainReadNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithX509ChainKlass = {
    xmlSecRespondWithX509Chain,			/* const xmlChar* name; */
    xmlSecNodeX509Data,				/* const xmlChar* nodeName; */
    xmlSecDSigNs,				/* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithX509ChainReadNode,	/* xmlSecXkmsRespondWithReadNodeMethod readNode; */
    xmlSecXkmsRespondWithDefaultWriteNode	/* xmlSecXkmsRespondWithWriteNodeMethod writeNode; */
};

/**
 * xmlSecXkmsRespondWithX509ChainGetKlass:
 *
 * The respond with X509Chain klass.
 *
 * Returns respond with X509Chain klass.
 */ 
xmlSecXkmsRespondWithId	
xmlSecXkmsRespondWithX509ChainGetKlass(void) {
    return(&xmlSecXkmsRespondWithX509ChainKlass);
}

static  int  
xmlSecXkmsRespondWithX509ChainReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithX509ChainId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, ctx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the ctx */

    /* todo 
    ctx->keyInfoWriteCtx;
    */
    return(0);
}

static  int  		xmlSecXkmsRespondWithX509CRLReadNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithX509CRLKlass = {
    xmlSecRespondWithX509CRL,			/* const xmlChar* name; */
    xmlSecNodeX509Data,				/* const xmlChar* nodeName; */
    xmlSecDSigNs,				/* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithX509CRLReadNode,	/* xmlSecXkmsRespondWithReadNodeMethod readNode; */
    xmlSecXkmsRespondWithDefaultWriteNode	/* xmlSecXkmsRespondWithWriteNodeMethod writeNode; */
};

/**
 * xmlSecXkmsRespondWithX509CRLGetKlass:
 *
 * The respond with X509CRL klass.
 *
 * Returns respond with X509CRL klass.
 */ 
xmlSecXkmsRespondWithId	
xmlSecXkmsRespondWithX509CRLGetKlass(void) {
    return(&xmlSecXkmsRespondWithX509CRLKlass);
}

static  int  
xmlSecXkmsRespondWithX509CRLReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr ctx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithX509CRLId, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, ctx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the ctx */

    /* todo 
    ctx->keyInfoWriteCtx;
    */
    return(0);
}

static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithPGPKlass = {
    xmlSecRespondWithPGP,			/* const xmlChar* name; */
    xmlSecNodePGPData,				/* const xmlChar* nodeName; */
    xmlSecDSigNs,				/* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithDefaultReadNode,	/* xmlSecXkmsRespondWithReadNodeMethod readNode; */
    xmlSecXkmsRespondWithDefaultWriteNode	/* xmlSecXkmsRespondWithWriteNodeMethod writeNode; */
};

/**
 * xmlSecXkmsRespondWithPGPGetKlass:
 *
 * The respond with PGP klass.
 *
 * Returns respond with PGP klass.
 */ 
xmlSecXkmsRespondWithId	
xmlSecXkmsRespondWithPGPGetKlass(void) {
    return(&xmlSecXkmsRespondWithPGPKlass);
}

static xmlSecXkmsRespondWithKlass xmlSecXkmsRespondWithSPKIKlass = {
    xmlSecRespondWithSPKI,			/* const xmlChar* name; */
    xmlSecNodeSPKIData,				/* const xmlChar* nodeName; */
    xmlSecDSigNs,				/* const xmlChar* nodeNs; */
    xmlSecXkmsRespondWithDefaultReadNode,	/* xmlSecXkmsRespondWithReadNodeMethod readNode; */
    xmlSecXkmsRespondWithDefaultWriteNode	/* xmlSecXkmsRespondWithWriteNodeMethod writeNode; */
};

/**
 * xmlSecXkmsRespondWithSPKIGetKlass:
 *
 * The respond with SPKI klass.
 *
 * Returns respond with SPKI klass.
 */ 
xmlSecXkmsRespondWithId	
xmlSecXkmsRespondWithSPKIGetKlass(void) {
    return(&xmlSecXkmsRespondWithSPKIKlass);
}

#endif /* XMLSEC_NO_XKMS */

