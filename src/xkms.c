/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * "XML Key Management Specification v 2.0" implementation
 *  http://www.w3.org/TR/xkms2/
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
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
static const xmlChar* xmlSecXkmsIds[] = { BAD_CAST "Id", NULL };

static int	xmlSecXkmsCtxReadLocateRequestNode		(xmlSecXkmsCtxPtr xkmsCtx,
							         xmlNodePtr node);
static int	xmlSecXkmsCtxReadQueryKeyBindingNode		(xmlSecXkmsCtxPtr xkmsCtx,
								 xmlNodePtr node);
static int	xmlSecXkmsCtxWriteLocateResultNode		(xmlSecXkmsCtxPtr xkmsCtx,
								 xmlNodePtr node);
static int	xmlSecXkmsCtxWriteUnverifiedKeyBindingNode	(xmlSecXkmsCtxPtr xkmsCtx,
								 xmlSecKeyPtr key,
							    	 xmlNodePtr node);
static int	xmlSecXkmsCtxWriteKeyInfoNode			(xmlSecXkmsCtxPtr xkmsCtx,
								 xmlSecKeyPtr key,
							    	 xmlNodePtr node);




/**
 * xmlSecXkmsCtxCreate:
 * @keysMngr: 		the pointer to keys manager.
 *
 * Creates XKMS processing context.
 * The caller is responsible for destroying returend object by calling 
 * #xmlSecXkmsCtxDestroy function.
 *
 * Returns pointer to newly allocated context object or NULL if an error
 * occurs.
 */
xmlSecXkmsCtxPtr	
xmlSecXkmsCtxCreate(xmlSecKeysMngrPtr keysMngr) {
    xmlSecXkmsCtxPtr xkmsCtx;
    int ret;
    
    xkmsCtx = (xmlSecXkmsCtxPtr) xmlMalloc(sizeof(xmlSecXkmsCtx));
    if(xkmsCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecXkmsCtx)=%d", 
		    sizeof(xmlSecXkmsCtx));
	return(NULL);
    }
    
    ret = xmlSecXkmsCtxInitialize(xkmsCtx, keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecXkmsCtxDestroy(xkmsCtx);
	return(NULL);   
    }
    return(xkmsCtx);    
}

/**
 * xmlSecXkmsCtxDestroy:
 * @xkmsCtx:		the pointer to XKMS processing context.
 *
 * Destroy context object created with #xmlSecXkmsCtxCreate function.
 */
void  
xmlSecXkmsCtxDestroy(xmlSecXkmsCtxPtr xkmsCtx) {
    xmlSecAssert(xkmsCtx != NULL);
    
    xmlSecXkmsCtxFinalize(xkmsCtx);
    xmlFree(xkmsCtx);
}

/**
 * xmlSecXkmsCtxInitialize:
 * @xkmsCtx:		the pointer to XKMS processing context.
 * @keysMngr: 		the pointer to keys manager.
 *
 * Initializes XKMS element processing context.
 * The caller is responsible for cleaing up returend object by calling 
 * #xmlSecXkmsCtxFinalize function.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkmsCtxInitialize(xmlSecXkmsCtxPtr xkmsCtx, xmlSecKeysMngrPtr keysMngr) {
    int ret;
    
    xmlSecAssert2(xkmsCtx != NULL, -1);
    
    memset(xkmsCtx, 0, sizeof(xmlSecXkmsCtx));

    /* initialize key info */
    ret = xmlSecKeyInfoCtxInitialize(&(xkmsCtx->keyInfoReadCtx), keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyInfoCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }
    xkmsCtx->keyInfoReadCtx.mode = xmlSecKeyInfoModeRead;
    
    ret = xmlSecKeyInfoCtxInitialize(&(xkmsCtx->keyInfoWriteCtx), keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyInfoCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }
    xkmsCtx->keyInfoWriteCtx.mode = xmlSecKeyInfoModeWrite;

    /* enabled RespondWith */
    ret = xmlSecPtrListInitialize(&(xkmsCtx->enabledRespondWith), xmlSecXkmsRespondWithIdListId);
    if(ret < 0) { 
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecPtrListInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* initialize keys list */
    ret = xmlSecPtrListInitialize(&(xkmsCtx->keys), xmlSecKeyPtrListId);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecPtrListInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }

    /* initialize RespondWith list */
    ret = xmlSecPtrListInitialize(&(xkmsCtx->respWithList), xmlSecXkmsRespondWithIdListId);
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
 * xmlSecXkmsCtxFinalize:
 * @xkmsCtx:		the pointer to XKMS processing context.
 *
 * Cleans up @xkmsCtx object.
 */
void 
xmlSecXkmsCtxFinalize(xmlSecXkmsCtxPtr xkmsCtx) {
    xmlSecAssert(xkmsCtx != NULL);

    xmlSecXkmsCtxReset(xkmsCtx);
    
    xmlSecKeyInfoCtxFinalize(&(xkmsCtx->keyInfoReadCtx));
    xmlSecKeyInfoCtxFinalize(&(xkmsCtx->keyInfoWriteCtx));
    xmlSecPtrListFinalize(&(xkmsCtx->enabledRespondWith));
    xmlSecPtrListFinalize(&(xkmsCtx->keys));
    xmlSecPtrListFinalize(&(xkmsCtx->respWithList));
    memset(xkmsCtx, 0, sizeof(xmlSecXkmsCtx));
}

/**
 * xmlSecXkmsCtxReset:
 * @xkmsCtx:		the pointer to XKMS processing context.
 *
 * Resets @xkmsCtx object, user settings are not touched.
 */
void 
xmlSecXkmsCtxReset(xmlSecXkmsCtxPtr xkmsCtx) {
    xmlSecAssert(xkmsCtx != NULL);
    
    xmlSecKeyInfoCtxReset(&(xkmsCtx->keyInfoReadCtx));
    xmlSecKeyInfoCtxReset(&(xkmsCtx->keyInfoWriteCtx));
    xmlSecPtrListEmpty(&(xkmsCtx->keys));
    xmlSecPtrListEmpty(&(xkmsCtx->respWithList));

    xkmsCtx->opaqueClientDataNode = NULL;    
    xkmsCtx->firtsMsgExtNode 	= NULL;
    xkmsCtx->firtsRespMechNode	= NULL;
    xkmsCtx->keyInfoNode	= NULL;

    if(xkmsCtx->result != NULL) {
	xmlFreeDoc(xkmsCtx->result);
	xkmsCtx->result = NULL;
    }
}

/**
 * xmlSecXkmsCtxCopyUserPref:
 * @dst:		the pointer to destination context.
 * @src:		the pointer to source context.
 * 
 * Copies user preference from @src context to @dst.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkmsCtxCopyUserPref(xmlSecXkmsCtxPtr dst, xmlSecXkmsCtxPtr src) {
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
 * xmlSecXkmsCtxLocate:
 * @xkmsCtx:		the pointer to XKMS processing context.
 * @node:		the pointer to <xkms:LocateRequest/> node.
 *
 * Process "locate key data" request from @node and returns key data 
 * in the #result member of the @xkmsCtx structure.
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
xmlSecXkmsCtxLocate(xmlSecXkmsCtxPtr xkmsCtx, xmlNodePtr node) {
    xmlSecKeyPtr key = NULL;
    int ret;

    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(xkmsCtx->result == NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    xmlSecAddIDs(node->doc, node, xmlSecXkmsIds);

    ret = xmlSecXkmsCtxReadLocateRequestNode(xkmsCtx, node);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsCtxReadLocateRequestNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto error;
    }

    /* now we are ready to search for key */
    if((xkmsCtx->keyInfoReadCtx.keysMngr != NULL) && (xkmsCtx->keyInfoReadCtx.keysMngr->getKey != NULL)) {
	key = (xkmsCtx->keyInfoReadCtx.keysMngr->getKey)(xkmsCtx->keyInfoNode, 
						         &(xkmsCtx->keyInfoReadCtx));
    }
    
    /* check that we got what we needed */
    if((key != NULL) && (!xmlSecKeyMatch(key, NULL, &(xkmsCtx->keyInfoReadCtx.keyReq)))) {
	xmlSecKeyDestroy(key);
	key = NULL;
    } else if(key != NULL) {
	ret = xmlSecPtrListAdd(&(xkmsCtx->keys), key);
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
    xmlSecAssert2(xkmsCtx->result == NULL, -1);
    xkmsCtx->result = xmlSecCreateTree(xmlSecNodeLocateResult, xmlSecXkmsNs);
    if(xkmsCtx->result == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCreateTree",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto error;
    }
            
    ret = xmlSecXkmsCtxWriteLocateResultNode(xkmsCtx, xmlDocGetRootElement(xkmsCtx->result)); 
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsCtxWriteLocateResultNode",
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
xmlSecXkmsCtxReadLocateRequestNode(xmlSecXkmsCtxPtr xkmsCtx, xmlNodePtr node) {
    xmlNodePtr cur;
    xmlChar* content;
    int ret;

    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(xkmsCtx->mode == xmlXkmsCtxModeLocateRequest, -1);
    xmlSecAssert2(xkmsCtx->opaqueClientDataNode == NULL, -1);
    xmlSecAssert2(xkmsCtx->firtsMsgExtNode == NULL, -1);
    xmlSecAssert2(xkmsCtx->firtsRespMechNode == NULL, -1);
    xmlSecAssert2(xkmsCtx->keyInfoNode == NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    cur = xmlSecGetNextElementNode(node->children);
    
    /* first node is optional <dsig:Signature/> node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeSignature, xmlSecDSigNs))) {
	/* todo: verify signature and make sure that correct data was signed */
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* next is zero or more <xkms:MessageExtension/> nodes */
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeMessageExtension, xmlSecXkmsNs))) {
	if(xkmsCtx->firtsMsgExtNode == NULL) {
	    xkmsCtx->firtsMsgExtNode = cur;
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* next is optional <xkms:OpaqueClientData/> node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeOpaqueClientData, xmlSecXkmsNs))) {
	xkmsCtx->opaqueClientDataNode = cur;
	cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next is zero or more <xkms:ResponseMechanism/> nodes */
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeResponseMechanism, xmlSecXkmsNs))) {
	if(xkmsCtx->firtsRespMechNode == NULL) {
	    xkmsCtx->firtsRespMechNode = cur;
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* next is zero or more <xkms:RespondWith/> nodes */
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeRespondWith, xmlSecXkmsNs))) {
	content = xmlNodeGetContent(cur);
	if(content != NULL) {
	    xmlSecXkmsRespondWithId id = xmlSecXkmsRespondWithIdUnknown;

	    /* todo: trim content? */
	    if(xmlSecPtrListGetSize(&(xkmsCtx->enabledRespondWith)) > 0) {
		id = xmlSecXkmsRespondWithIdListFindByName(&(xkmsCtx->enabledRespondWith), content);
	    } else {
		id = xmlSecXkmsRespondWithIdListFindByName(xmlSecXkmsRespondWithIdsGet(), content);	
	    }
	    xmlFree(content);

	    if(id != xmlSecXkmsRespondWithIdUnknown) {	
		ret = xmlSecXkmsRespondWithReadNode(id, xkmsCtx, cur);
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
    ret = xmlSecXkmsCtxReadQueryKeyBindingNode(xkmsCtx, cur);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsCtxReadQueryKeyBindingNode",
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
xmlSecXkmsCtxReadQueryKeyBindingNode(xmlSecXkmsCtxPtr xkmsCtx, xmlNodePtr node) {
    xmlNodePtr cur;
    
    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(xkmsCtx->keyInfoNode == NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    cur = xmlSecGetNextElementNode(node->children);
    
    /* first node is optional <dsig:KeyInfo/> node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeKeyInfo, xmlSecDSigNs))) {
	xkmsCtx->keyInfoNode = cur;
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
xmlSecXkmsCtxWriteLocateResultNode(xmlSecXkmsCtxPtr xkmsCtx, xmlNodePtr node) {
    xmlSecSize pos, size;
    xmlSecKeyPtr key;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(xkmsCtx->mode == xmlXkmsCtxModeLocateRequest, -1);
    xmlSecAssert2(node != NULL, -1);
    
    /* todo: add <xkms:LocateResult/> node attributes */

    /* todo: <dsig:Signature/> */
    /* todo: <xkms:MessageExtension/> */
    
    /* <xkms:OpaqueClientData/> */
    if(xkmsCtx->opaqueClientDataNode != NULL) {
	xmlChar* content;
	
	content = xmlNodeGetContent(xkmsCtx->opaqueClientDataNode);	
	if(content == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    	NULL,
			"xmlNodeGetContent",
			XMLSEC_ERRORS_R_XML_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(xkmsCtx->opaqueClientDataNode)));
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
    size = xmlSecPtrListGetSize(&(xkmsCtx->keys));
    for(pos = 0; pos < size; ++pos) {
	key = (xmlSecKeyPtr)xmlSecPtrListGetItem(&(xkmsCtx->keys), pos);
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

	ret = xmlSecXkmsCtxWriteUnverifiedKeyBindingNode(xkmsCtx, key, cur);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecXkmsCtxWriteUnverifiedKeyBindingNode",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);  	
	}
    }

    return(0);
}

static int 
xmlSecXkmsCtxWriteUnverifiedKeyBindingNode(xmlSecXkmsCtxPtr xkmsCtx, xmlSecKeyPtr key,
					   xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(xkmsCtx->mode == xmlXkmsCtxModeLocateRequest, -1);
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

    ret = xmlSecXkmsCtxWriteKeyInfoNode(xkmsCtx, key, cur);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsCtxWriteKeyInfoNode",
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
xmlSecXkmsCtxWriteKeyInfoNode(xmlSecXkmsCtxPtr xkmsCtx, xmlSecKeyPtr key, xmlNodePtr node) {
    int ret;

    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(xkmsCtx->mode == xmlXkmsCtxModeLocateRequest, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* add child nodes as requested in <xkms:RespondWith/> nodes */
    ret = xmlSecXkmsRespondWithIdListWrite(&(xkmsCtx->respWithList), xkmsCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsRespondWithIdListWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }

    ret = xmlSecKeyInfoNodeWrite(node, key, &(xkmsCtx->keyInfoWriteCtx));
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
 * xmlSecXkmsCtxValidate:
 * @xkmsCtx:		the pointer to XKMS processing context.
 * @node:		the pointer to <xkms:ValidateRequest/> node.
 *
 * Process "locate and validate key data" request from @node and returns key data 
 * in the #result member of the @xkmsCtx structure.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkmsCtxValidate(xmlSecXkmsCtxPtr xkmsCtx, xmlNodePtr node) {
    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    xkmsCtx->mode = xmlXkmsCtxModeValidateRequest;
    
    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecXkmsCtxLocate",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

/**
 * xmlSecXkmsCtxDebugDump:
 * @xkmsCtx:		the pointer to XKMS processing context.
 * @output:		the pointer to output FILE.
 *
 * Prints the debug information about @xkmsCtx to @output.
 */
void 
xmlSecXkmsCtxDebugDump(xmlSecXkmsCtxPtr xkmsCtx, FILE* output) {
    xmlSecAssert(xkmsCtx != NULL);
    xmlSecAssert(output != NULL);
    
    switch(xkmsCtx->mode) {
	case xmlXkmsCtxModeLocateRequest:
	    fprintf(output, "= XKMS LOCATE REQUEST CONTEXT\n");
	    break;
	case xmlXkmsCtxModeValidateRequest:
	    fprintf(output, "= XKMS VALIDATE REQUEST CONTEXT\n");
	    break;
    }
    fprintf(output, "== flags: 0x%08x\n", xkmsCtx->flags);
    fprintf(output, "== flags2: 0x%08x\n", xkmsCtx->flags2);

    fprintf(output, "== Key Info Read Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(xkmsCtx->keyInfoReadCtx), output);
    
    fprintf(output, "== Key Info Write Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(xkmsCtx->keyInfoWriteCtx), output);

    if(xmlSecPtrListGetSize(&(xkmsCtx->enabledRespondWith)) > 0) {
	fprintf(output, "== Enabled RespondWith: ");
	xmlSecTransformIdListDebugDump(&(xkmsCtx->enabledRespondWith), output);
    } else {
	fprintf(output, "== Enabled RespondWith: all\n");
    }

    fprintf(output, "== RespondWith List:\n");
    xmlSecPtrListDebugDump(&(xkmsCtx->respWithList), output);

    fprintf(output, "== Keys:\n");
    xmlSecPtrListDebugDump(&(xkmsCtx->keys), output);

}

/**
 * xmlSecXkmsCtxDebugXmlDump:
 * @xkmsCtx:		the pointer to XKMS processing context.
 * @output:		the pointer to output FILE.
 *
 * Prints the debug information about @xkmsCtx to @output in XML format.
 */
void 
xmlSecXkmsCtxDebugXmlDump(xmlSecXkmsCtxPtr xkmsCtx, FILE* output) {
    xmlSecAssert(xkmsCtx != NULL);
    xmlSecAssert(output != NULL);

    switch(xkmsCtx->mode) {
	case xmlXkmsCtxModeLocateRequest:
	    fprintf(output, "<XkmsLocateRequestContext>\n");
	    break;
	case xmlXkmsCtxModeValidateRequest:
	    fprintf(output, "<XkmsValidateRequestContext>\n");
	    break;
    }
    fprintf(output, "<Flags>%08x</Flags>\n", xkmsCtx->flags);
    fprintf(output, "<Flags2>%08x</Flags2>\n", xkmsCtx->flags2);

    fprintf(output, "<KeyInfoReadCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(xkmsCtx->keyInfoReadCtx), output);
    fprintf(output, "</KeyInfoReadCtx>\n");

    fprintf(output, "<KeyInfoWriteCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(xkmsCtx->keyInfoWriteCtx), output);
    fprintf(output, "</KeyInfoWriteCtx>\n");

    if(xmlSecPtrListGetSize(&(xkmsCtx->enabledRespondWith)) > 0) {
	fprintf(output, "<EnabledRespondWith>\n");
	xmlSecTransformIdListDebugXmlDump(&(xkmsCtx->enabledRespondWith), output);
	fprintf(output, "</EnabledRespondWith>\n");
    } else {
	fprintf(output, "<EnabledRespondWith>all</EnabledRespondWith>\n");
    }

    fprintf(output, "<RespondWithList>\n");
    xmlSecPtrListDebugXmlDump(&(xkmsCtx->respWithList), output);
    fprintf(output, "</RespondWithList>\n");

    fprintf(output, "<Keys>\n");
    xmlSecPtrListDebugXmlDump(&(xkmsCtx->keys), output);
    fprintf(output, "</Keys\n");

    switch(xkmsCtx->mode) {
	case xmlXkmsCtxModeLocateRequest:
	    fprintf(output, "</XkmsLocateRequestContext>\n");
	    break;
	case xmlXkmsCtxModeValidateRequest:
	    fprintf(output, "</XkmsValidateRequestContext>\n");
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
int  
xmlSecXkmsRespondWithReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsCtxPtr xkmsCtx,
			      xmlNodePtr node) {
    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    if(id->readNode != NULL) {
	return((id->readNode)(id, xkmsCtx, node));
    }
    return(0);
}

int 
xmlSecXkmsRespondWithWriteNode(xmlSecXkmsRespondWithId id, xmlSecXkmsCtxPtr xkmsCtx,
			     xmlNodePtr node) {
    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    if(id->writeNode != NULL) {
	return((id->writeNode)(id, xkmsCtx, node));
    }
    return(0);
}

void 
xmlSecXkmsRespondWithDebugDump(xmlSecXkmsRespondWithId id, FILE* output) {
    xmlSecAssert(id != xmlSecXkmsRespondWithIdUnknown);
    xmlSecAssert(output != NULL);

    fprintf(output, "=== RespondWith: %s\n", xmlSecErrorsSafeString(id->name));
}

void 
xmlSecXkmsRespondWithDebugXmlDump(xmlSecXkmsRespondWithId id, FILE* output) {
    xmlSecAssert(id != xmlSecXkmsRespondWithIdUnknown);
    xmlSecAssert(output != NULL);

    fprintf(output, "<RespondWith>%s</RespondWith>\n", xmlSecErrorsSafeString(id->name));
}

int 
xmlSecXkmsRespondWithDefaultReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsCtxPtr xkmsCtx,
			    xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    ret = xmlSecXkmsRespondWithIdListFind(&(xkmsCtx->respWithList), id);
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
    
    ret = xmlSecPtrListAdd(&(xkmsCtx->respWithList), id);
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
xmlSecXkmsRespondWithDefaultWriteNode(xmlSecXkmsRespondWithId id, xmlSecXkmsCtxPtr xkmsCtx,
			    xmlNodePtr node) {
    xmlNodePtr cur;

    xmlSecAssert2(id != xmlSecXkmsRespondWithIdUnknown, -1);
    xmlSecAssert2(id->nodeName != NULL, -1);
    xmlSecAssert2(xkmsCtx != NULL, -1);
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
xmlSecXkmsRespondWithIdListWrite(xmlSecPtrListPtr list, xmlSecXkmsCtxPtr xkmsCtx, xmlNodePtr node) {
    xmlSecXkmsRespondWithId id;
    xmlSecSize i, size;
    int ret;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecXkmsRespondWithIdListId), -1);
    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
	id = (xmlSecXkmsRespondWithId)xmlSecPtrListGetItem(list, i);
	if(id !=  xmlSecXkmsRespondWithIdUnknown) {
	    ret = xmlSecXkmsRespondWithWriteNode(id, xkmsCtx, node);
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
								 xmlSecXkmsCtxPtr xkmsCtx,
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
xmlSecXkmsRespondWithKeyValueReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsCtxPtr xkmsCtx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithKeyValueId, -1);
    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, xkmsCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the xkmsCtx to look for a public or private 
     * key and to write a public key
     */
    xkmsCtx->keyInfoReadCtx.keyReq.keyType  |= (xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate);
    xkmsCtx->keyInfoWriteCtx.keyReq.keyType |= xmlSecKeyDataTypePublic;

    return(0);
}

static  int  		xmlSecXkmsRespondWithPrivateKeyReadNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsCtxPtr xkmsCtx,
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
xmlSecXkmsRespondWithPrivateKeyReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsCtxPtr xkmsCtx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithPrivateKeyId, -1);
    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, xkmsCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the xkmsCtx to look for a private 
     * key and to write a private key
     */
    xkmsCtx->keyInfoReadCtx.keyReq.keyType  |= xmlSecKeyDataTypePrivate;
    xkmsCtx->keyInfoWriteCtx.keyReq.keyType |= xmlSecKeyDataTypePrivate;

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
								 xmlSecXkmsCtxPtr xkmsCtx,
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
xmlSecXkmsRespondWithX509CertReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsCtxPtr xkmsCtx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithX509CertId, -1);
    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, xkmsCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the xkmsCtx */

    /* todo 
    xkmsCtx->keyInfoWriteCtx;
    */
    return(0);
}

static  int  		xmlSecXkmsRespondWithX509ChainReadNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsCtxPtr xkmsCtx,
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
xmlSecXkmsRespondWithX509ChainReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsCtxPtr xkmsCtx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithX509ChainId, -1);
    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, xkmsCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the xkmsCtx */

    /* todo 
    xkmsCtx->keyInfoWriteCtx;
    */
    return(0);
}

static  int  		xmlSecXkmsRespondWithX509CRLReadNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsCtxPtr xkmsCtx,
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
xmlSecXkmsRespondWithX509CRLReadNode(xmlSecXkmsRespondWithId id, xmlSecXkmsCtxPtr xkmsCtx,
				      xmlNodePtr node) {
    int ret;

    xmlSecAssert2(id == xmlSecXkmsRespondWithX509CRLId, -1);
    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* do usual stuff */
    ret = xmlSecXkmsRespondWithDefaultReadNode(id, xkmsCtx, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecXkmsRespondWithKlassGetName(id)),
		    "xmlSecXkmsRespondWithDefaultReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);  	
    }
    
    /* and now set some parameters in the xkmsCtx */

    /* todo 
    xkmsCtx->keyInfoWriteCtx;
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

