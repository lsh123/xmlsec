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
static const xmlChar*		xmlSecXkmsIds[] = { BAD_CAST "Id", NULL };


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
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecXkmsCtxLocate(xmlSecXkmsCtxPtr xkmsCtx, xmlNodePtr node) {
    xmlSecAssert2(xkmsCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    xkmsCtx->mode = xmlXkmsCtxModeLocateRequest;
    
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

