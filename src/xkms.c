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

/* The ID attribute in XKMS is 'Id' */
static const xmlChar* xmlSecXkmsIds[] = { BAD_CAST "Id", NULL };

static int	xmlSecXkmsCtxReadLocateRequestNode	(xmlSecXkmsCtxPtr xkmsCtx,
							 xmlNodePtr node);
static int	xmlSecXkmsCtxReadQueryKeyBindingNode	(xmlSecXkmsCtxPtr xkmsCtx,
							 xmlNodePtr node);
static int	xmlSecXkmsCtxWriteLocateResultNode	(xmlSecXkmsCtxPtr xkmsCtx,
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
    xmlSecPtrListFinalize(&(xkmsCtx->keys));
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
    
    xkmsCtx->firtsMsgExtNode 	= NULL;
    xkmsCtx->firtsRespMechNode	= NULL;
    xkmsCtx->firtsRespWithNode	= NULL;
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
	goto done;
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
	    goto done;
	}
    }


done:
    /* write back the result */
    if(xkmsCtx->result == NULL) {
        xkmsCtx->result = xmlSecCreateTree(xmlSecNodeLocateResult, xmlSecXkmsNs);
	if(xkmsCtx->result == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
		        NULL,
			"xmlSecCreateTree",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
            
	ret = xmlSecXkmsCtxWriteLocateResultNode(xkmsCtx, xmlDocGetRootElement(xkmsCtx->result)); 
	if(ret < 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
		        NULL,
			"xmlSecXkmsCtxWriteLocateResultNode",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }

    return(0);
}

static int 
xmlSecXkmsCtxReadLocateRequestNode(xmlSecXkmsCtxPtr xkmsCtx, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(xkmsCtx->mode == xmlXkmsCtxModeLocateRequest, -1);
    xmlSecAssert2(xkmsCtx->firtsMsgExtNode == NULL, -1);
    xmlSecAssert2(xkmsCtx->firtsRespMechNode == NULL, -1);
    xmlSecAssert2(xkmsCtx->firtsRespWithNode == NULL, -1);
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
	/* todo */
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
	if(xkmsCtx->firtsRespWithNode == NULL) {
	    xkmsCtx->firtsRespWithNode = cur;
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
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(xkmsCtx->mode == xmlXkmsCtxModeLocateRequest, -1);
    xmlSecAssert2(node != NULL, -1);
    
    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecXkmsCtxLocate",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
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

#endif /* XMLSEC_NO_XKMS */

