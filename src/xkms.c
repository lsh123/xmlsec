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
#include <xmlsec/xkms.h>
#include <xmlsec/errors.h>



/**************************************************************************
 *
 * 
 *
 *************************************************************************/

/* The ID attribute in XKMS is 'Id' */
static const xmlChar* xmlSecXkissServerIds[] = { BAD_CAST "Id", NULL };

static int	xmlSecXkissServerCtxReadLocateRequestNode		(xmlSecXkissServerCtxPtr xkissServerCtx,
							         xmlNodePtr node);
static int	xmlSecXkissServerCtxReadQueryKeyBindingNode		(xmlSecXkissServerCtxPtr xkissServerCtx,
								 xmlNodePtr node);
static int	xmlSecXkissServerCtxWriteLocateResultNode		(xmlSecXkissServerCtxPtr xkissServerCtx,
								 xmlNodePtr node);
static int	xmlSecXkissServerCtxWriteUnverifiedKeyBindingNode	(xmlSecXkissServerCtxPtr xkissServerCtx,
								 xmlSecKeyPtr key,
							    	 xmlNodePtr node);
static int	xmlSecXkissServerCtxWriteKeyInfoNode			(xmlSecXkissServerCtxPtr xkissServerCtx,
								 xmlSecKeyPtr key,
							    	 xmlNodePtr node);




/**
 * xmlSecXkissServerCtxCreate:
 * @keysMngr: 		the pointer to keys manager.
 *
 * Creates XKMS/XKISS request server side processing context.
 * The caller is responsible for destroying returend object by calling 
 * #xmlSecXkissServerCtxDestroy function.
 *
 * Returns pointer to newly allocated context object or NULL if an error
 * occurs.
 */
xmlSecXkissServerCtxPtr	
xmlSecXkissServerCtxCreate(xmlSecKeysMngrPtr keysMngr) {
    xmlSecXkissServerCtxPtr xkissServerCtx;
    int ret;
    
    xkissServerCtx = (xmlSecXkissServerCtxPtr) xmlMalloc(sizeof(xmlSecXkissServerCtx));
    if(xkissServerCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecXkissServerCtx)=%d", 
		    sizeof(xmlSecXkissServerCtx));
	return(NULL);
    }
    
    ret = xmlSecXkissServerCtxInitialize(xkissServerCtx, keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkissServerCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecXkissServerCtxDestroy(xkissServerCtx);
	return(NULL);   
    }
    return(xkissServerCtx);    
}

/**
 * xmlSecXkissServerCtxDestroy:
 * @xkissServerCtx:		the pointer to XKMS/XKISS processing context.
 *
 * Destroy context object created with #xmlSecXkissServerCtxCreate function.
 */
void  
xmlSecXkissServerCtxDestroy(xmlSecXkissServerCtxPtr xkissServerCtx) {
    xmlSecAssert(xkissServerCtx != NULL);
    
    xmlSecXkissServerCtxFinalize(xkissServerCtx);
    xmlFree(xkissServerCtx);
}

/**
 * xmlSecXkissServerCtxInitialize:
 * @xkissServerCtx:		the pointer to XKMS/XKISS processing context.
 * @keysMngr: 		the pointer to keys manager.
 *
 * Initializes XKMS/XKISS element processing context.
 * The caller is responsible for cleaing up returend object by calling 
 * #xmlSecXkissServerCtxFinalize function.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkissServerCtxInitialize(xmlSecXkissServerCtxPtr xkissServerCtx, xmlSecKeysMngrPtr keysMngr) {
    int ret;
    
    xmlSecAssert2(xkissServerCtx != NULL, -1);
    
    memset(xkissServerCtx, 0, sizeof(xmlSecXkissServerCtx));

    /* initialize key info */
    ret = xmlSecKeyInfoCtxInitialize(&(xkissServerCtx->keyInfoReadCtx), keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyInfoCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }
    xkissServerCtx->keyInfoReadCtx.mode = xmlSecKeyInfoModeRead;
    
    ret = xmlSecKeyInfoCtxInitialize(&(xkissServerCtx->keyInfoWriteCtx), keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyInfoCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }
    xkissServerCtx->keyInfoWriteCtx.mode = xmlSecKeyInfoModeWrite;

    /* enabled RespondWith */
    ret = xmlSecPtrListInitialize(&(xkissServerCtx->enabledRespondWith), xmlSecXkmsRespondWithIdListId);
    if(ret < 0) { 
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecPtrListInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* initialize keys list */
    ret = xmlSecPtrListInitialize(&(xkissServerCtx->keys), xmlSecKeyPtrListId);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecPtrListInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }

    /* initialize RespondWith list */
    ret = xmlSecPtrListInitialize(&(xkissServerCtx->respWithList), xmlSecXkmsRespondWithIdListId);
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
 * xmlSecXkissServerCtxFinalize:
 * @xkissServerCtx:		the pointer to XKMS/XKISS processing context.
 *
 * Cleans up @xkissServerCtx object.
 */
void 
xmlSecXkissServerCtxFinalize(xmlSecXkissServerCtxPtr xkissServerCtx) {
    xmlSecAssert(xkissServerCtx != NULL);

    xmlSecXkissServerCtxReset(xkissServerCtx);
    
    xmlSecKeyInfoCtxFinalize(&(xkissServerCtx->keyInfoReadCtx));
    xmlSecKeyInfoCtxFinalize(&(xkissServerCtx->keyInfoWriteCtx));
    xmlSecPtrListFinalize(&(xkissServerCtx->enabledRespondWith));
    xmlSecPtrListFinalize(&(xkissServerCtx->keys));
    xmlSecPtrListFinalize(&(xkissServerCtx->respWithList));
    memset(xkissServerCtx, 0, sizeof(xmlSecXkissServerCtx));
}

/**
 * xmlSecXkissServerCtxReset:
 * @xkissServerCtx:		the pointer to XKMS/XKISS processing context.
 *
 * Resets @xkissServerCtx object, user settings are not touched.
 */
void 
xmlSecXkissServerCtxReset(xmlSecXkissServerCtxPtr xkissServerCtx) {
    xmlSecAssert(xkissServerCtx != NULL);
    
    xmlSecKeyInfoCtxReset(&(xkissServerCtx->keyInfoReadCtx));
    xmlSecKeyInfoCtxReset(&(xkissServerCtx->keyInfoWriteCtx));
    xmlSecPtrListEmpty(&(xkissServerCtx->keys));
    xmlSecPtrListEmpty(&(xkissServerCtx->respWithList));

    xkissServerCtx->opaqueClientDataNode = NULL;    
    xkissServerCtx->firtsMsgExtNode 	= NULL;
    xkissServerCtx->firtsRespMechNode	= NULL;
    xkissServerCtx->keyInfoNode	= NULL;

    if(xkissServerCtx->result != NULL) {
	xmlFreeDoc(xkissServerCtx->result);
	xkissServerCtx->result = NULL;
    }
}

/**
 * xmlSecXkissServerCtxCopyUserPref:
 * @dst:		the pointer to destination context.
 * @src:		the pointer to source context.
 * 
 * Copies user preference from @src context to @dst.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkissServerCtxCopyUserPref(xmlSecXkissServerCtxPtr dst, xmlSecXkissServerCtxPtr src) {
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
 * xmlSecXkissServerCtxLocate:
 * @xkissServerCtx:		the pointer to XKMS/XKISS processing context.
 * @node:		the pointer to <xkms:LocateRequest/> node.
 *
 * Process "locate key data" request from @node and returns key data 
 * in the #result member of the @xkissServerCtx structure.
 * 
 * <xkms:LocateRequest Id Service Nonce? OriginalRequestId? ResponseLimit? >
 * 	<dsig:Signature/>?
 *	<xkms:MessageExtension/>*
 * 	<xkms:OpaqueClientData/>?
 *	<xkms:ResponseMechanism/>*
 * 	<xkms:RespondWith/>*
 *	<xkms:PendingNotification Mechanism Identifier />?
 *	<xkms:QueryKeyBinding Id? >
 * 		<dsig:KeyInfo/>?
 *		<xkms:KeyUsage/>*
 *		<xkms:UseKeyWith Application Identifier />*
 *		<xkms:TimeInstant Time />?
 *	</xkms:QueryKeyBinding>
 * </xkms:LocateRequest> 
 *
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkissServerCtxLocate(xmlSecXkissServerCtxPtr xkissServerCtx, xmlNodePtr node) {
    xmlSecKeyPtr key = NULL;
    int ret;

    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(xkissServerCtx->result == NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    xmlSecAddIDs(node->doc, node, xmlSecXkissServerIds);

    ret = xmlSecXkissServerCtxReadLocateRequestNode(xkissServerCtx, node);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkissServerCtxReadLocateRequestNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto error;
    }

    /* now we are ready to search for key */
    if((xkissServerCtx->keyInfoReadCtx.keysMngr != NULL) && (xkissServerCtx->keyInfoReadCtx.keysMngr->getKey != NULL)) {
	key = (xkissServerCtx->keyInfoReadCtx.keysMngr->getKey)(xkissServerCtx->keyInfoNode, 
						         &(xkissServerCtx->keyInfoReadCtx));
    }
    
    /* check that we got what we needed */
    if((key != NULL) && (!xmlSecKeyMatch(key, NULL, &(xkissServerCtx->keyInfoReadCtx.keyReq)))) {
	xmlSecKeyDestroy(key);
	key = NULL;
    } else if(key != NULL) {
	ret = xmlSecPtrListAdd(&(xkissServerCtx->keys), key);
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
    xmlSecAssert2(xkissServerCtx->result == NULL, -1);
    xkissServerCtx->result = xmlSecCreateTree(xmlSecNodeLocateResult, xmlSecXkmsNs);
    if(xkissServerCtx->result == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCreateTree",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto error;
    }
            
    ret = xmlSecXkissServerCtxWriteLocateResultNode(xkissServerCtx, xmlDocGetRootElement(xkissServerCtx->result)); 
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkissServerCtxWriteLocateResultNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto error;
    }
    return(0);

error:
    /* todo: write error result */

    return(0);
}

static int 
xmlSecXkissServerCtxReadLocateRequestNode(xmlSecXkissServerCtxPtr xkissServerCtx, xmlNodePtr node) {
    xmlNodePtr cur;
    xmlChar* content;
    int ret;

    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(xkissServerCtx->mode == xmlXkissServerCtxModeLocateRequest, -1);
    xmlSecAssert2(xkissServerCtx->opaqueClientDataNode == NULL, -1);
    xmlSecAssert2(xkissServerCtx->firtsMsgExtNode == NULL, -1);
    xmlSecAssert2(xkissServerCtx->firtsRespMechNode == NULL, -1);
    xmlSecAssert2(xkissServerCtx->keyInfoNode == NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    cur = xmlSecGetNextElementNode(node->children);
    
    /* first node is optional <dsig:Signature/> node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeSignature, xmlSecDSigNs))) {
	/* todo: verify signature and make sure that correct data was signed */
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* next is zero or more <xkms:MessageExtension/> nodes */
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeMessageExtension, xmlSecXkmsNs))) {
	if(xkissServerCtx->firtsMsgExtNode == NULL) {
	    xkissServerCtx->firtsMsgExtNode = cur;
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* next is optional <xkms:OpaqueClientData/> node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeOpaqueClientData, xmlSecXkmsNs))) {
	xkissServerCtx->opaqueClientDataNode = cur;
	cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next is zero or more <xkms:ResponseMechanism/> nodes */
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeResponseMechanism, xmlSecXkmsNs))) {
	if(xkissServerCtx->firtsRespMechNode == NULL) {
	    xkissServerCtx->firtsRespMechNode = cur;
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* next is zero or more <xkms:RespondWith/> nodes */
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeRespondWith, xmlSecXkmsNs))) {
	content = xmlNodeGetContent(cur);
	if(content != NULL) {
	    xmlSecXkmsRespondWithId id = xmlSecXkmsRespondWithIdUnknown;

	    /* todo: trim content? */
	    if(xmlSecPtrListGetSize(&(xkissServerCtx->enabledRespondWith)) > 0) {
		id = xmlSecXkmsRespondWithIdListFindByName(&(xkissServerCtx->enabledRespondWith), content);
	    } else {
		id = xmlSecXkmsRespondWithIdListFindByName(xmlSecXkmsRespondWithIdsGet(), content);	
	    }
	    xmlFree(content);

	    if(id != xmlSecXkmsRespondWithIdUnknown) {	
		ret = xmlSecXkmsRespondWithReadNode(id, xkissServerCtx, cur);
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
    ret = xmlSecXkissServerCtxReadQueryKeyBindingNode(xkissServerCtx, cur);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkissServerCtxReadQueryKeyBindingNode",
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
xmlSecXkissServerCtxReadQueryKeyBindingNode(xmlSecXkissServerCtxPtr xkissServerCtx, xmlNodePtr node) {
    xmlNodePtr cur;
    
    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(xkissServerCtx->keyInfoNode == NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    cur = xmlSecGetNextElementNode(node->children);
    
    /* first node is optional <dsig:KeyInfo/> node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeKeyInfo, xmlSecDSigNs))) {
	xkissServerCtx->keyInfoNode = cur;
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

static int	
xmlSecXkissServerCtxWriteLocateResultNode(xmlSecXkissServerCtxPtr xkissServerCtx, xmlNodePtr node) {
    xmlSecSize pos, size;
    xmlSecKeyPtr key;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(xkissServerCtx->mode == xmlXkissServerCtxModeLocateRequest, -1);
    xmlSecAssert2(node != NULL, -1);
    
    /* todo: add <xkms:LocateResult/> node attributes */

    /* todo: <dsig:Signature/> */
    /* todo: <xkms:MessageExtension/> */
    
    /* <xkms:OpaqueClientData/> */
    if(xkissServerCtx->opaqueClientDataNode != NULL) {
	xmlChar* content;
	
	content = xmlNodeGetContent(xkissServerCtx->opaqueClientDataNode);	
	if(content == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    	NULL,
			"xmlNodeGetContent",
			XMLSEC_ERRORS_R_XML_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(xkissServerCtx->opaqueClientDataNode)));
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
    size = xmlSecPtrListGetSize(&(xkissServerCtx->keys));
    for(pos = 0; pos < size; ++pos) {
	key = (xmlSecKeyPtr)xmlSecPtrListGetItem(&(xkissServerCtx->keys), pos);
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

	ret = xmlSecXkissServerCtxWriteUnverifiedKeyBindingNode(xkissServerCtx, key, cur);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecXkissServerCtxWriteUnverifiedKeyBindingNode",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);  	
	}
    }

    return(0);
}

static int 
xmlSecXkissServerCtxWriteUnverifiedKeyBindingNode(xmlSecXkissServerCtxPtr xkissServerCtx, xmlSecKeyPtr key,
					   xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(xkissServerCtx->mode == xmlXkissServerCtxModeLocateRequest, -1);
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

    ret = xmlSecXkissServerCtxWriteKeyInfoNode(xkissServerCtx, key, cur);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkissServerCtxWriteKeyInfoNode",
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
xmlSecXkissServerCtxWriteKeyInfoNode(xmlSecXkissServerCtxPtr xkissServerCtx, xmlSecKeyPtr key, xmlNodePtr node) {
    int ret;

    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(xkissServerCtx->mode == xmlXkissServerCtxModeLocateRequest, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* add child nodes as requested in <xkms:RespondWith/> nodes */
    ret = xmlSecXkmsRespondWithIdListWrite(&(xkissServerCtx->respWithList), xkissServerCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsRespondWithIdListWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }

    ret = xmlSecKeyInfoNodeWrite(node, key, &(xkissServerCtx->keyInfoWriteCtx));
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
 * xmlSecXkissServerCtxValidate:
 * @xkissServerCtx:		the pointer to XKMS/XKISS processing context.
 * @node:		the pointer to <xkms:ValidateRequest/> node.
 *
 * Process "locate and validate key data" request from @node and returns key data 
 * in the #result member of the @xkissServerCtx structure.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkissServerCtxValidate(xmlSecXkissServerCtxPtr xkissServerCtx, xmlNodePtr node) {
    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    xkissServerCtx->mode = xmlXkissServerCtxModeValidateRequest;
    
    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecXkissServerCtxLocate",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

/**
 * xmlSecXkissServerCtxDebugDump:
 * @xkissServerCtx:		the pointer to XKMS/XKISS processing context.
 * @output:		the pointer to output FILE.
 *
 * Prints the debug information about @xkissServerCtx to @output.
 */
void 
xmlSecXkissServerCtxDebugDump(xmlSecXkissServerCtxPtr xkissServerCtx, FILE* output) {
    xmlSecAssert(xkissServerCtx != NULL);
    xmlSecAssert(output != NULL);
    
    switch(xkissServerCtx->mode) {
	case xmlXkissServerCtxModeLocateRequest:
	    fprintf(output, "= XKMS/XKISS SERVER LOCATE REQUEST CONTEXT\n");
	    break;
	case xmlXkissServerCtxModeValidateRequest:
	    fprintf(output, "= XKMS/XKISS SERVER VALIDATE REQUEST CONTEXT\n");
	    break;
    }
    fprintf(output, "== flags: 0x%08x\n", xkissServerCtx->flags);
    fprintf(output, "== flags2: 0x%08x\n", xkissServerCtx->flags2);

    fprintf(output, "== Key Info Read Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(xkissServerCtx->keyInfoReadCtx), output);
    
    fprintf(output, "== Key Info Write Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(xkissServerCtx->keyInfoWriteCtx), output);

    if(xmlSecPtrListGetSize(&(xkissServerCtx->enabledRespondWith)) > 0) {
	fprintf(output, "== Enabled RespondWith: ");
	xmlSecTransformIdListDebugDump(&(xkissServerCtx->enabledRespondWith), output);
    } else {
	fprintf(output, "== Enabled RespondWith: all\n");
    }

    fprintf(output, "== RespondWith List:\n");
    xmlSecPtrListDebugDump(&(xkissServerCtx->respWithList), output);

    fprintf(output, "== Keys:\n");
    xmlSecPtrListDebugDump(&(xkissServerCtx->keys), output);

}

/**
 * xmlSecXkissServerCtxDebugXmlDump:
 * @xkissServerCtx:		the pointer to XKMS/XKISS processing context.
 * @output:		the pointer to output FILE.
 *
 * Prints the debug information about @xkissServerCtx to @output in XML format.
 */
void 
xmlSecXkissServerCtxDebugXmlDump(xmlSecXkissServerCtxPtr xkissServerCtx, FILE* output) {
    xmlSecAssert(xkissServerCtx != NULL);
    xmlSecAssert(output != NULL);

    switch(xkissServerCtx->mode) {
	case xmlXkissServerCtxModeLocateRequest:
	    fprintf(output, "<XkissServerLocateRequestContext>\n");
	    break;
	case xmlXkissServerCtxModeValidateRequest:
	    fprintf(output, "<XkissServerValidateRequestContext>\n");
	    break;
    }
    fprintf(output, "<Flags>%08x</Flags>\n", xkissServerCtx->flags);
    fprintf(output, "<Flags2>%08x</Flags2>\n", xkissServerCtx->flags2);

    fprintf(output, "<KeyInfoReadCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(xkissServerCtx->keyInfoReadCtx), output);
    fprintf(output, "</KeyInfoReadCtx>\n");

    fprintf(output, "<KeyInfoWriteCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(xkissServerCtx->keyInfoWriteCtx), output);
    fprintf(output, "</KeyInfoWriteCtx>\n");

    if(xmlSecPtrListGetSize(&(xkissServerCtx->enabledRespondWith)) > 0) {
	fprintf(output, "<EnabledRespondWith>\n");
	xmlSecTransformIdListDebugXmlDump(&(xkissServerCtx->enabledRespondWith), output);
	fprintf(output, "</EnabledRespondWith>\n");
    } else {
	fprintf(output, "<EnabledRespondWith>all</EnabledRespondWith>\n");
    }

    fprintf(output, "<RespondWithList>\n");
    xmlSecPtrListDebugXmlDump(&(xkissServerCtx->respWithList), output);
    fprintf(output, "</RespondWithList>\n");

    fprintf(output, "<Keys>\n");
    xmlSecPtrListDebugXmlDump(&(xkissServerCtx->keys), output);
    fprintf(output, "</Keys\n");

    switch(xkissServerCtx->mode) {
	case xmlXkissServerCtxModeLocateRequest:
	    fprintf(output, "</XkissServerLocateRequestContext>\n");
	    break;
	case xmlXkissServerCtxModeValidateRequest:
	    fprintf(output, "</XkissServerValidateRequestContext>\n");
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
 * @xkissServerCtx:	the XKISS request processing context.
 * @node:		the pointer to <xkiss:RespondWith/> node.
 *
 * Reads the content of the <xkiss:RespondWith/> @node.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int  
xmlSecXkmsRespondWithReadNode(xmlSecXkmsRespondWithId id, xmlSecXkissServerCtxPtr xkissServerCtx,
			      xmlNodePtr node) {
    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    if(id->readNode != NULL) {
	return((id->readNode)(id, xkissServerCtx, node));
    }
    return(0);
}

/**
 * xmlSecXkmsRespondWithWriteNode:
 * @id:			the RespondWith class.
 * @xkissServerCtx:	the XKISS request processing context.
 * @node:		the pointer to <xkiss:RespondWith/> node.
 *
 * Writes the content of the <xkiss:RespondWith/> @node.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkmsRespondWithWriteNode(xmlSecXkmsRespondWithId id, xmlSecXkissServerCtxPtr xkissServerCtx,
			     xmlNodePtr node) {
    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    if(id->writeNode != NULL) {
	return((id->writeNode)(id, xkissServerCtx, node));
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
xmlSecXkmsRespondWithDefaultReadNode(xmlSecXkmsRespondWithId id, xmlSecXkissServerCtxPtr xkissServerCtx,
			    xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    ret = xmlSecXkmsRespondWithIdListFind(&(xkissServerCtx->respWithList), id);
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
    
    ret = xmlSecPtrListAdd(&(xkissServerCtx->respWithList), id);
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
xmlSecXkmsRespondWithDefaultWriteNode(xmlSecXkmsRespondWithId id, xmlSecXkissServerCtxPtr xkissServerCtx,
			    xmlNodePtr node) {
    xmlNodePtr cur;

    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(id->nodeName != NULL, -1);
    xmlSecAssert2(xkissServerCtx != NULL, -1);
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
xmlSecXkmsRespondWithIdListWrite(xmlSecPtrListPtr list, xmlSecXkissServerCtxPtr xkissServerCtx, xmlNodePtr node) {
    xmlSecXkmsRespondWithId id;
    xmlSecSize i, size;
    int ret;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecXkmsRespondWithIdListId), -1);
    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
	id = (xmlSecXkmsRespondWithId)xmlSecPtrListGetItem(list, i);
	if(id !=  xmlSecXkmsRespondWithIdUnknown) {
	    ret = xmlSecXkmsRespondWithWriteNode(id, xkissServerCtx, node);
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
								 xmlSecXkissServerCtxPtr xkissServerCtx,
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
xmlSecXkmsRespondWithKeyValueReadNode(xmlSecXkmsRespondWithId id, xmlSecXkissServerCtxPtr xkissServerCtx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithKeyValueId, -1);
    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, xkissServerCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the xkissServerCtx to look for a public or private 
     * key and to write a public key
     */
    xkissServerCtx->keyInfoReadCtx.keyReq.keyType  |= (xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate);
    xkissServerCtx->keyInfoWriteCtx.keyReq.keyType |= xmlSecKeyDataTypePublic;

    return(0);
}

static  int  		xmlSecXkmsRespondWithPrivateKeyReadNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkissServerCtxPtr xkissServerCtx,
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
xmlSecXkmsRespondWithPrivateKeyReadNode(xmlSecXkmsRespondWithId id, xmlSecXkissServerCtxPtr xkissServerCtx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithPrivateKeyId, -1);
    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, xkissServerCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the xkissServerCtx to look for a private 
     * key and to write a private key
     */
    xkissServerCtx->keyInfoReadCtx.keyReq.keyType  |= xmlSecKeyDataTypePrivate;
    xkissServerCtx->keyInfoWriteCtx.keyReq.keyType |= xmlSecKeyDataTypePrivate;

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
								 xmlSecXkissServerCtxPtr xkissServerCtx,
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
xmlSecXkmsRespondWithX509CertReadNode(xmlSecXkmsRespondWithId id, xmlSecXkissServerCtxPtr xkissServerCtx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithX509CertId, -1);
    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, xkissServerCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the xkissServerCtx */

    /* todo 
    xkissServerCtx->keyInfoWriteCtx;
    */
    return(0);
}

static  int  		xmlSecXkmsRespondWithX509ChainReadNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkissServerCtxPtr xkissServerCtx,
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
xmlSecXkmsRespondWithX509ChainReadNode(xmlSecXkmsRespondWithId id, xmlSecXkissServerCtxPtr xkissServerCtx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithX509ChainId, -1);
    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, xkissServerCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the xkissServerCtx */

    /* todo 
    xkissServerCtx->keyInfoWriteCtx;
    */
    return(0);
}

static  int  		xmlSecXkmsRespondWithX509CRLReadNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkissServerCtxPtr xkissServerCtx,
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
xmlSecXkmsRespondWithX509CRLReadNode(xmlSecXkmsRespondWithId id, xmlSecXkissServerCtxPtr xkissServerCtx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithX509CRLId, -1);
    xmlSecAssert2(xkissServerCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, xkissServerCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the xkissServerCtx */

    /* todo 
    xkissServerCtx->keyInfoWriteCtx;
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

