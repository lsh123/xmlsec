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
 *      <xkmsTimeInstant Time>?
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
 *          <xkmsTimeInstant Time>?
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

static int	xmlSecXkmsServerCtxReadLocateRequestNode	(xmlSecXkmsServerCtxPtr xkmsServerCtx,
							         xmlNodePtr node);
static int	xmlSecXkmsServerCtxReadRespondWithNodes		(xmlSecXkmsServerCtxPtr xkmsServerCtx, 
								 xmlNodePtr* node);
static int	xmlSecXkmsServerCtxReadQueryKeyBindingNode	(xmlSecXkmsServerCtxPtr xkmsServerCtx,
								 xmlNodePtr node);
static int	xmlSecXkmsServerCtxWriteLocateResultNode	(xmlSecXkmsServerCtxPtr xkmsServerCtx,
								 xmlNodePtr node);
static int	xmlSecXkmsServerCtxWriteUnverifiedKeyBindingNode(xmlSecXkmsServerCtxPtr xkmsServerCtx,
								 xmlSecKeyPtr key,
							    	 xmlNodePtr node);
static int	xmlSecXkmsServerCtxWriteKeyInfoNode		(xmlSecXkmsServerCtxPtr xkmsServerCtx,
								 xmlSecKeyPtr key,
							    	 xmlNodePtr node);




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
    xmlSecXkmsServerCtxPtr xkmsServerCtx;
    int ret;
    
    xkmsServerCtx = (xmlSecXkmsServerCtxPtr) xmlMalloc(sizeof(xmlSecXkmsServerCtx));
    if(xkmsServerCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecXkmsServerCtx)=%d", 
		    sizeof(xmlSecXkmsServerCtx));
	return(NULL);
    }
    
    ret = xmlSecXkmsServerCtxInitialize(xkmsServerCtx, keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsServerCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecXkmsServerCtxDestroy(xkmsServerCtx);
	return(NULL);   
    }
    return(xkmsServerCtx);    
}

/**
 * xmlSecXkmsServerCtxDestroy:
 * @xkmsServerCtx:		the pointer to XKMS processing context.
 *
 * Destroy context object created with #xmlSecXkmsServerCtxCreate function.
 */
void  
xmlSecXkmsServerCtxDestroy(xmlSecXkmsServerCtxPtr xkmsServerCtx) {
    xmlSecAssert(xkmsServerCtx != NULL);
    
    xmlSecXkmsServerCtxFinalize(xkmsServerCtx);
    xmlFree(xkmsServerCtx);
}

/**
 * xmlSecXkmsServerCtxInitialize:
 * @xkmsServerCtx:		the pointer to XKMS processing context.
 * @keysMngr: 		the pointer to keys manager.
 *
 * Initializes XKMS element processing context.
 * The caller is responsible for cleaing up returend object by calling 
 * #xmlSecXkmsServerCtxFinalize function.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkmsServerCtxInitialize(xmlSecXkmsServerCtxPtr xkmsServerCtx, xmlSecKeysMngrPtr keysMngr) {
    int ret;
    
    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    
    memset(xkmsServerCtx, 0, sizeof(xmlSecXkmsServerCtx));

    /* initialize key info */
    ret = xmlSecKeyInfoCtxInitialize(&(xkmsServerCtx->keyInfoReadCtx), keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyInfoCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }
    xkmsServerCtx->keyInfoReadCtx.mode = xmlSecKeyInfoModeRead;
    
    ret = xmlSecKeyInfoCtxInitialize(&(xkmsServerCtx->keyInfoWriteCtx), keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyInfoCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }
    xkmsServerCtx->keyInfoWriteCtx.mode = xmlSecKeyInfoModeWrite;

    /* enabled RespondWith */
    ret = xmlSecPtrListInitialize(&(xkmsServerCtx->enabledRespondWith), xmlSecXkmsRespondWithIdListId);
    if(ret < 0) { 
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecPtrListInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* initialize keys list */
    ret = xmlSecPtrListInitialize(&(xkmsServerCtx->keys), xmlSecKeyPtrListId);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecPtrListInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }

    /* initialize RespondWith list */
    ret = xmlSecPtrListInitialize(&(xkmsServerCtx->respWithList), xmlSecXkmsRespondWithIdListId);
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
 * @xkmsServerCtx:		the pointer to XKMS processing context.
 *
 * Cleans up @xkmsServerCtx object.
 */
void 
xmlSecXkmsServerCtxFinalize(xmlSecXkmsServerCtxPtr xkmsServerCtx) {
    xmlSecAssert(xkmsServerCtx != NULL);

    xmlSecXkmsServerCtxReset(xkmsServerCtx);
    
    xmlSecKeyInfoCtxFinalize(&(xkmsServerCtx->keyInfoReadCtx));
    xmlSecKeyInfoCtxFinalize(&(xkmsServerCtx->keyInfoWriteCtx));
    xmlSecPtrListFinalize(&(xkmsServerCtx->enabledRespondWith));
    xmlSecPtrListFinalize(&(xkmsServerCtx->keys));
    xmlSecPtrListFinalize(&(xkmsServerCtx->respWithList));
    memset(xkmsServerCtx, 0, sizeof(xmlSecXkmsServerCtx));
}

/**
 * xmlSecXkmsServerCtxReset:
 * @xkmsServerCtx:		the pointer to XKMS processing context.
 *
 * Resets @xkmsServerCtx object, user settings are not touched.
 */
void 
xmlSecXkmsServerCtxReset(xmlSecXkmsServerCtxPtr xkmsServerCtx) {
    xmlSecAssert(xkmsServerCtx != NULL);
    
    xmlSecKeyInfoCtxReset(&(xkmsServerCtx->keyInfoReadCtx));
    xmlSecKeyInfoCtxReset(&(xkmsServerCtx->keyInfoWriteCtx));
    xmlSecPtrListEmpty(&(xkmsServerCtx->keys));
    xmlSecPtrListEmpty(&(xkmsServerCtx->respWithList));

    xkmsServerCtx->opaqueClientDataNode = NULL;    
    xkmsServerCtx->firtsMsgExtNode 	= NULL;
    xkmsServerCtx->firtsRespMechNode	= NULL;
    xkmsServerCtx->keyInfoNode	= NULL;

    if(xkmsServerCtx->result != NULL) {
	xmlFreeDoc(xkmsServerCtx->result);
	xkmsServerCtx->result = NULL;
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
 * xmlSecXkmsServerCtxLocate:
 * @xkmsServerCtx:	the pointer to XKMS processing context.
 * @node:		the pointer to <xkms:LocateRequest/> node.
 *
 * Process "locate key data" request from @node and returns key data 
 * in the #result member of the @xkmsServerCtx structure.
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
 *          <xkmsTimeInstant Time>?
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkmsServerCtxLocate(xmlSecXkmsServerCtxPtr xkmsServerCtx, xmlNodePtr node) {
    xmlSecKeyPtr key = NULL;
    int ret;

    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(xkmsServerCtx->result == NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    xmlSecAddIDs(node->doc, node, xmlSecXkmsServerIds);

    ret = xmlSecXkmsServerCtxReadLocateRequestNode(xkmsServerCtx, node);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsServerCtxReadLocateRequestNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto error;
    }

    /* now we are ready to search for key */
    if((xkmsServerCtx->keyInfoReadCtx.keysMngr != NULL) && (xkmsServerCtx->keyInfoReadCtx.keysMngr->getKey != NULL)) {
	key = (xkmsServerCtx->keyInfoReadCtx.keysMngr->getKey)(xkmsServerCtx->keyInfoNode, 
						         &(xkmsServerCtx->keyInfoReadCtx));
    }
    
    /* check that we got what we needed */
    if((key != NULL) && (!xmlSecKeyMatch(key, NULL, &(xkmsServerCtx->keyInfoReadCtx.keyReq)))) {
	xmlSecKeyDestroy(key);
	key = NULL;
    } else if(key != NULL) {
	ret = xmlSecPtrListAdd(&(xkmsServerCtx->keys), key);
	if(ret < 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecPtrListAdd",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
		        XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecKeyDestroy(key);
	    key = NULL;
	    goto error;
	}
    }

    /* write back the keys */
    xmlSecAssert2(xkmsServerCtx->result == NULL, -1);
    xkmsServerCtx->result = xmlSecCreateTree(xmlSecNodeLocateResult, xmlSecXkmsNs);
    if(xkmsServerCtx->result == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCreateTree",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto error;
    }
            
    ret = xmlSecXkmsServerCtxWriteLocateResultNode(xkmsServerCtx, xmlDocGetRootElement(xkmsServerCtx->result)); 
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsServerCtxWriteLocateResultNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto error;
    }
    return(0);

error:
    /* todo: write error result */

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
 *          <xkmsTimeInstant Time>?
 */
static int 
xmlSecXkmsServerCtxReadLocateRequestNode(xmlSecXkmsServerCtxPtr xkmsServerCtx, xmlNodePtr node) {
    xmlNodePtr cur;
    xmlChar* content;
    int ret;

    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(xkmsServerCtx->mode == xmlXkmsServerCtxModeLocateRequest, -1);
    xmlSecAssert2(node != NULL, -1);
    
    cur = xmlSecGetNextElementNode(node->children);
    
    /* first node is optional <dsig:Signature/> node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeSignature, xmlSecDSigNs))) {
	/* todo: verify signature and make sure that correct data was signed */
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* next is zero or more <xkms:MessageExtension/> nodes */
    xmlSecAssert2(xkmsServerCtx->firtsMsgExtNode == NULL, -1);
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeMessageExtension, xmlSecXkmsNs))) {
	if(xkmsServerCtx->firtsMsgExtNode == NULL) {
	    xkmsServerCtx->firtsMsgExtNode = cur;
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* next is optional <xkms:OpaqueClientData/> node */
    xmlSecAssert2(xkmsServerCtx->opaqueClientDataNode == NULL, -1);
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeOpaqueClientData, xmlSecXkmsNs))) {
	xkmsServerCtx->opaqueClientDataNode = cur;
	cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next is zero or more <xkms:ResponseMechanism/> nodes */
    xmlSecAssert2(xkmsServerCtx->firtsRespMechNode == NULL, -1);
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeResponseMechanism, xmlSecXkmsNs))) {
	if(xkmsServerCtx->firtsRespMechNode == NULL) {
	    xkmsServerCtx->firtsRespMechNode = cur;
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* next is zero or more <xkms:RespondWith/> nodes */
    ret = xmlSecXkmsServerCtxReadRespondWithNodes(xkmsServerCtx, &cur);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsServerCtxReadRespondWithNodes",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* next is optional <xkms:PendingNotification/> node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodePendingNotification, xmlSecXkmsNs))) {
	/* todo */
	cur = xmlSecGetNextElementNode(cur->next);
    }

    /* the last is a required <xkms:QueryKeyBinding/> node */
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
    ret = xmlSecXkmsServerCtxReadQueryKeyBindingNode(xkmsServerCtx, cur);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsServerCtxReadQueryKeyBindingNode",
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

static int
xmlSecXkmsServerCtxReadRespondWithNodes(xmlSecXkmsServerCtxPtr xkmsServerCtx, xmlNodePtr* node) {
    xmlNodePtr cur;
    xmlChar* content;
    int ret;

    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(xkmsServerCtx->mode == xmlXkmsServerCtxModeLocateRequest, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = (*node);
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeRespondWith, xmlSecXkmsNs))) {
	content = xmlNodeGetContent(cur);
	if(content != NULL) {
	    xmlSecXkmsRespondWithId id = xmlSecXkmsRespondWithIdUnknown;

	    /* todo: trim content? */
	    if(xmlSecPtrListGetSize(&(xkmsServerCtx->enabledRespondWith)) > 0) {
		id = xmlSecXkmsRespondWithIdListFindByName(&(xkmsServerCtx->enabledRespondWith), content);
	    } else {
		id = xmlSecXkmsRespondWithIdListFindByName(xmlSecXkmsRespondWithIdsGet(), content);	
	    }
	    xmlFree(content);

	    if(id != xmlSecXkmsRespondWithIdUnknown) {	
		ret = xmlSecXkmsRespondWithReadNode(id, xkmsServerCtx, cur);
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
		TODO: add a flag
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

static int 
xmlSecXkmsServerCtxReadQueryKeyBindingNode(xmlSecXkmsServerCtxPtr xkmsServerCtx, xmlNodePtr node) {
    xmlNodePtr cur;
    
    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(xkmsServerCtx->keyInfoNode == NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    cur = xmlSecGetNextElementNode(node->children);
    
    /* first node is optional <dsig:KeyInfo/> node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeKeyInfo, xmlSecDSigNs))) {
	xkmsServerCtx->keyInfoNode = cur;
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* next is zero or more <xkms:KeyUsage/> nodes */
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeKeyUsage, xmlSecXkmsNs))) {
	/* todo: convert key usage in the xmlSecKeyInfoCtx */
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* next is zero or more <xkms:UseKeyWith/> nodes */
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeUseKeyWith, xmlSecXkmsNs))) {
	/* todo: convert key usage in the xmlSecKeyInfoCtx */
	cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next is optional <xkms:TimeInstant/> node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeTimeInstant, xmlSecXkmsNs))) {
	/* todo */
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
 */ 
static int
xmlSecXkmsServerCtxWriteLocateResultNode(xmlSecXkmsServerCtxPtr xkmsServerCtx, xmlNodePtr node) {
    xmlSecSize pos, size;
    xmlSecKeyPtr key;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(xkmsServerCtx->mode == xmlXkmsServerCtxModeLocateRequest, -1);
    xmlSecAssert2(node != NULL, -1);
    
    /* todo: add <xkms:LocateResult/> node attributes */

    /* todo: <dsig:Signature/> */
    /* todo: <xkms:MessageExtension/> */
    
    /* <xkms:OpaqueClientData/> */
    if(xkmsServerCtx->opaqueClientDataNode != NULL) {
	xmlChar* content;
	
	content = xmlNodeGetContent(xkmsServerCtx->opaqueClientDataNode);	
	if(content == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    	NULL,
			"xmlNodeGetContent",
			XMLSEC_ERRORS_R_XML_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(xkmsServerCtx->opaqueClientDataNode)));
	    return(-1);  	
	}

	/* copy node content "as-is" */
        cur = xmlSecAddChild(node, xmlSecNodeOpaqueClientData, xmlSecXkmsNs);
        if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    	NULL,
			"xmlSecAddChild",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeOpaqueClientData));
	    xmlFree(content);
	    return(-1);  	
	}
	xmlNodeSetContent(cur, content);
	xmlFree(content);
    }

    /* todo: <xkms:RequestSignatureValue> */
    
    /* write keys in <xkms:UnverifiedKeyBinding> nodes */
    size = xmlSecPtrListGetSize(&(xkmsServerCtx->keys));
    for(pos = 0; pos < size; ++pos) {
	key = (xmlSecKeyPtr)xmlSecPtrListGetItem(&(xkmsServerCtx->keys), pos);
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

	ret = xmlSecXkmsServerCtxWriteUnverifiedKeyBindingNode(xkmsServerCtx, key, cur);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecXkmsServerCtxWriteUnverifiedKeyBindingNode",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);  	
	}
    }

    return(0);
}

static int 
xmlSecXkmsServerCtxWriteUnverifiedKeyBindingNode(xmlSecXkmsServerCtxPtr xkmsServerCtx, xmlSecKeyPtr key,
					   xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(xkmsServerCtx->mode == xmlXkmsServerCtxModeLocateRequest, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

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

    ret = xmlSecXkmsServerCtxWriteKeyInfoNode(xkmsServerCtx, key, cur);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsServerCtxWriteKeyInfoNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* todo: <xkms:KeyUsage/> node */
    /* todo: <xkms:UseKeyWith/> node */
    /* todo: <xkms:ValidityInterval/> node */
    return(0);
}

static int 
xmlSecXkmsServerCtxWriteKeyInfoNode(xmlSecXkmsServerCtxPtr xkmsServerCtx, xmlSecKeyPtr key, xmlNodePtr node) {
    int ret;

    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(xkmsServerCtx->mode == xmlXkmsServerCtxModeLocateRequest, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* add child nodes as requested in <xkms:RespondWith/> nodes */
    ret = xmlSecXkmsRespondWithIdListWrite(&(xkmsServerCtx->respWithList), xkmsServerCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsRespondWithIdListWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }

    ret = xmlSecKeyInfoNodeWrite(node, key, &(xkmsServerCtx->keyInfoWriteCtx));
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
 * xmlSecXkmsServerCtxValidate:
 * @xkmsServerCtx:		the pointer to XKMS processing context.
 * @node:		the pointer to <xkms:ValidateRequest/> node.
 *
 * Process "locate and validate key data" request from @node and returns key data 
 * in the #result member of the @xkmsServerCtx structure.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkmsServerCtxValidate(xmlSecXkmsServerCtxPtr xkmsServerCtx, xmlNodePtr node) {
    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    xkmsServerCtx->mode = xmlXkmsServerCtxModeValidateRequest;
    
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
 * @xkmsServerCtx:		the pointer to XKMS processing context.
 * @output:		the pointer to output FILE.
 *
 * Prints the debug information about @xkmsServerCtx to @output.
 */
void 
xmlSecXkmsServerCtxDebugDump(xmlSecXkmsServerCtxPtr xkmsServerCtx, FILE* output) {
    xmlSecAssert(xkmsServerCtx != NULL);
    xmlSecAssert(output != NULL);
    
    switch(xkmsServerCtx->mode) {
	case xmlXkmsServerCtxModeLocateRequest:
	    fprintf(output, "= XKMS SERVER LOCATE REQUEST CONTEXT\n");
	    break;
	case xmlXkmsServerCtxModeValidateRequest:
	    fprintf(output, "= XKMS SERVER VALIDATE REQUEST CONTEXT\n");
	    break;
    }
    fprintf(output, "== flags: 0x%08x\n", xkmsServerCtx->flags);
    fprintf(output, "== flags2: 0x%08x\n", xkmsServerCtx->flags2);

    fprintf(output, "== Key Info Read Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(xkmsServerCtx->keyInfoReadCtx), output);
    
    fprintf(output, "== Key Info Write Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(xkmsServerCtx->keyInfoWriteCtx), output);

    if(xmlSecPtrListGetSize(&(xkmsServerCtx->enabledRespondWith)) > 0) {
	fprintf(output, "== Enabled RespondWith: ");
	xmlSecTransformIdListDebugDump(&(xkmsServerCtx->enabledRespondWith), output);
    } else {
	fprintf(output, "== Enabled RespondWith: all\n");
    }

    fprintf(output, "== RespondWith List:\n");
    xmlSecPtrListDebugDump(&(xkmsServerCtx->respWithList), output);

    fprintf(output, "== Keys:\n");
    xmlSecPtrListDebugDump(&(xkmsServerCtx->keys), output);

}

/**
 * xmlSecXkmsServerCtxDebugXmlDump:
 * @xkmsServerCtx:		the pointer to XKMS processing context.
 * @output:		the pointer to output FILE.
 *
 * Prints the debug information about @xkmsServerCtx to @output in XML format.
 */
void 
xmlSecXkmsServerCtxDebugXmlDump(xmlSecXkmsServerCtxPtr xkmsServerCtx, FILE* output) {
    xmlSecAssert(xkmsServerCtx != NULL);
    xmlSecAssert(output != NULL);

    switch(xkmsServerCtx->mode) {
	case xmlXkmsServerCtxModeLocateRequest:
	    fprintf(output, "<XkmsServerLocateRequestContext>\n");
	    break;
	case xmlXkmsServerCtxModeValidateRequest:
	    fprintf(output, "<XkmsServerValidateRequestContext>\n");
	    break;
    }
    fprintf(output, "<Flags>%08x</Flags>\n", xkmsServerCtx->flags);
    fprintf(output, "<Flags2>%08x</Flags2>\n", xkmsServerCtx->flags2);

    fprintf(output, "<KeyInfoReadCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(xkmsServerCtx->keyInfoReadCtx), output);
    fprintf(output, "</KeyInfoReadCtx>\n");

    fprintf(output, "<KeyInfoWriteCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(xkmsServerCtx->keyInfoWriteCtx), output);
    fprintf(output, "</KeyInfoWriteCtx>\n");

    if(xmlSecPtrListGetSize(&(xkmsServerCtx->enabledRespondWith)) > 0) {
	fprintf(output, "<EnabledRespondWith>\n");
	xmlSecTransformIdListDebugXmlDump(&(xkmsServerCtx->enabledRespondWith), output);
	fprintf(output, "</EnabledRespondWith>\n");
    } else {
	fprintf(output, "<EnabledRespondWith>all</EnabledRespondWith>\n");
    }

    fprintf(output, "<RespondWithList>\n");
    xmlSecPtrListDebugXmlDump(&(xkmsServerCtx->respWithList), output);
    fprintf(output, "</RespondWithList>\n");

    fprintf(output, "<Keys>\n");
    xmlSecPtrListDebugXmlDump(&(xkmsServerCtx->keys), output);
    fprintf(output, "</Keys\n");

    switch(xkmsServerCtx->mode) {
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
 * @xkmsServerCtx:	the XKMS request processing context.
 * @node:		the pointer to <xkms:RespondWith/> node.
 *
 * Reads the content of the <xkms:RespondWith/> @node.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int  
xmlSecXkmsRespondWithReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr xkmsServerCtx,
			      xmlNodePtr node) {
    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    if(id->readNode != NULL) {
	return((id->readNode)(id, xkmsServerCtx, node));
    }
    return(0);
}

/**
 * xmlSecXkmsRespondWithWriteNode:
 * @id:			the RespondWith class.
 * @xkmsServerCtx:	the XKMS request processing context.
 * @node:		the pointer to <xkms:RespondWith/> node.
 *
 * Writes the content of the <xkms:RespondWith/> @node.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkmsRespondWithWriteNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr xkmsServerCtx,
			     xmlNodePtr node) {
    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    if(id->writeNode != NULL) {
	return((id->writeNode)(id, xkmsServerCtx, node));
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
xmlSecXkmsRespondWithDefaultReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr xkmsServerCtx,
			    xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    ret = xmlSecXkmsRespondWithIdListFind(&(xkmsServerCtx->respWithList), id);
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
    
    ret = xmlSecPtrListAdd(&(xkmsServerCtx->respWithList), id);
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
xmlSecXkmsRespondWithDefaultWriteNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr xkmsServerCtx,
			    xmlNodePtr node) {
    xmlNodePtr cur;

    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(id->nodeName != NULL, -1);
    xmlSecAssert2(xkmsServerCtx != NULL, -1);
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
xmlSecXkmsRespondWithIdListWrite(xmlSecPtrListPtr list, xmlSecXkmsServerCtxPtr xkmsServerCtx, xmlNodePtr node) {
    xmlSecXkmsRespondWithId id;
    xmlSecSize i, size;
    int ret;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecXkmsRespondWithIdListId), -1);
    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
	id = (xmlSecXkmsRespondWithId)xmlSecPtrListGetItem(list, i);
	if(id !=  xmlSecXkmsRespondWithIdUnknown) {
	    ret = xmlSecXkmsRespondWithWriteNode(id, xkmsServerCtx, node);
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
								 xmlSecXkmsServerCtxPtr xkmsServerCtx,
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
xmlSecXkmsRespondWithKeyValueReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr xkmsServerCtx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithKeyValueId, -1);
    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, xkmsServerCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the xkmsServerCtx to look for a public or private 
     * key and to write a public key
     */
    xkmsServerCtx->keyInfoReadCtx.keyReq.keyType  |= (xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate);
    xkmsServerCtx->keyInfoWriteCtx.keyReq.keyType |= xmlSecKeyDataTypePublic;

    return(0);
}

static  int  		xmlSecXkmsRespondWithPrivateKeyReadNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsServerCtxPtr xkmsServerCtx,
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
xmlSecXkmsRespondWithPrivateKeyReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr xkmsServerCtx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithPrivateKeyId, -1);
    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, xkmsServerCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the xkmsServerCtx to look for a private 
     * key and to write a private key
     */
    xkmsServerCtx->keyInfoReadCtx.keyReq.keyType  |= xmlSecKeyDataTypePrivate;
    xkmsServerCtx->keyInfoWriteCtx.keyReq.keyType |= xmlSecKeyDataTypePrivate;

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
								 xmlSecXkmsServerCtxPtr xkmsServerCtx,
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
xmlSecXkmsRespondWithX509CertReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr xkmsServerCtx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithX509CertId, -1);
    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, xkmsServerCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the xkmsServerCtx */

    /* todo 
    xkmsServerCtx->keyInfoWriteCtx;
    */
    return(0);
}

static  int  		xmlSecXkmsRespondWithX509ChainReadNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsServerCtxPtr xkmsServerCtx,
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
xmlSecXkmsRespondWithX509ChainReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr xkmsServerCtx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithX509ChainId, -1);
    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, xkmsServerCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the xkmsServerCtx */

    /* todo 
    xkmsServerCtx->keyInfoWriteCtx;
    */
    return(0);
}

static  int  		xmlSecXkmsRespondWithX509CRLReadNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsServerCtxPtr xkmsServerCtx,
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
xmlSecXkmsRespondWithX509CRLReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsServerCtxPtr xkmsServerCtx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithX509CRLId, -1);
    xmlSecAssert2(xkmsServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, xkmsServerCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the xkmsServerCtx */

    /* todo 
    xkmsServerCtx->keyInfoWriteCtx;
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

