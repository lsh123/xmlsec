/** 
 * XMLSec library
 *
 * "XML Digital Signature" implementation
 *  http://www.w3.org/TR/xmldsig-core/
 *  http://www.w3.org/Signature/Overview.html
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_XMLDSIG

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
#include <xmlsec/membuf.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/errors.h>

/**************************************************************************
 *
 * xmlSecDSigCtx
 *
 *************************************************************************/
xmlSecDSigCtxPtr	
xmlSecDSigCtxCreate(xmlSecKeysMngrPtr keysMngr) {
    xmlSecDSigCtxPtr ctx;
    int ret;
    
    ctx = (xmlSecDSigCtxPtr) xmlMalloc(sizeof(xmlSecDSigCtx));
    if(ctx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecDSigCtx)=%d", 
		    sizeof(xmlSecDSigCtx));
	return(NULL);
    }
    
    ret = xmlSecDSigCtxInitialize(ctx, keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecDSigCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecDSigCtxDestroy(ctx);
	return(NULL);   
    }
    return(ctx);    
}

void  
xmlSecDSigCtxDestroy(xmlSecDSigCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);
    
    xmlSecDSigCtxFinalize(ctx);
    xmlFree(ctx);
}

int 
xmlSecDSigCtxInitialize(xmlSecDSigCtxPtr ctx, xmlSecKeysMngrPtr keysMngr) {
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    
    memset(ctx, 0, sizeof(xmlSecDSigCtx));

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
    /* it's not wise to write private key :) */
    ctx->keyInfoWriteCtx.keyReq.keyType = xmlSecKeyDataTypePublic;

    /* initializes transforms ctx */
    ret = xmlSecTransformCtxInitialize(&(ctx->signTransformCtx));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }

    xmlSecPtrListInitialize(&(ctx->references), xmlSecDSigReferenceCtxListId);
    xmlSecPtrListInitialize(&(ctx->manifests), xmlSecDSigReferenceCtxListId);

    /* TODO: set other values */	    
    return(0);
}

void 
xmlSecDSigCtxFinalize(xmlSecDSigCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    xmlSecTransformCtxFinalize(&(ctx->signTransformCtx));
    xmlSecKeyInfoCtxFinalize(&(ctx->keyInfoReadCtx));
    xmlSecKeyInfoCtxFinalize(&(ctx->keyInfoWriteCtx));
    xmlSecPtrListFinalize(&(ctx->references));
    xmlSecPtrListFinalize(&(ctx->manifests));

    if((ctx->dontDestroyC14NMethod != 0) && (ctx->c14nMethod != NULL)) {
	xmlSecTransformDestroy(ctx->c14nMethod, 1);
    }    
    if((ctx->dontDestroySignMethod != 0) && (ctx->signMethod != NULL)) {
	xmlSecTransformDestroy(ctx->signMethod, 1);
    }    
    if(ctx->signKey != NULL) {
	xmlSecKeyDestroy(ctx->signKey);
    }
    if(ctx->id != NULL) {
	xmlFree(ctx->id);
    }	
    /* TODO: cleanup all */
    memset(ctx, 0, sizeof(xmlSecDSigCtx));
}

int 
xmlSecDSigCtxSign(xmlSecDSigCtxPtr ctx, xmlNodePtr tmpl) {
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->result == NULL, -1);
    xmlSecAssert2(tmpl != NULL, -1);

    /* TODO */
    return(0);    
}

int 
xmlSecDSigCtxVerify(xmlSecDSigCtxPtr ctx, xmlNodePtr node) {
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    return(0);
}

void 
xmlSecDSigCtxDebugDump(xmlSecDSigCtxPtr ctx, FILE* output) {
    xmlSecAssert(ctx != NULL);

    if(ctx->sign) {    
	fprintf(output, "= SIGNATURE CONTEXT\n");
    } else {
	fprintf(output, "= VERIFICATION CONTEXT\n");
    }
    switch(ctx->status) {
	case xmlDSigStatusUnknown:
	    fprintf(output, "== Status: unknown\n");
	    break;
	case xmlDSigStatusSucceeded:
	    fprintf(output, "== Status: succeeded\n");
	    break;
	case xmlDSigStatusInvalid:
	    fprintf(output, "== Status: invalid\n");
	    break;
	case xmlDSigStatusFailed:
	    fprintf(output, "== Status: failed\n");
	    break;
    }
    if(ctx->id != NULL) {
	fprintf(output, "== Id: \"%s\"\n", ctx->id);
    }
    
    fprintf(output, "== Key Info Read Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(ctx->keyInfoReadCtx), output);
    fprintf(output, "== Key Info Write Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(ctx->keyInfoWriteCtx), output);

    xmlSecTransformCtxDebugDump(&(ctx->signTransformCtx), output);
    
    if((ctx->result != NULL) && 
       (xmlSecBufferGetData(ctx->result) != NULL)) {

	fprintf(output, "== Result - start buffer:\n");
	fwrite(xmlSecBufferGetData(ctx->result), 
	       xmlSecBufferGetSize(ctx->result), 1,
	       output);
	fprintf(output, "\n== Result - end buffer\n");
    } else {
	fprintf(output, "== Result: %d bytes\n",
		xmlSecBufferGetSize(ctx->result));
    }
    
    /* todo: preSignMemBufMethod */
    /* todo: references and manifests */
    /* todo: sign key */
}

void 
xmlSecDSigCtxDebugXmlDump(xmlSecDSigCtxPtr ctx, FILE* output) {
    xmlSecAssert(ctx != NULL);

    if(ctx->sign) {    
	fprintf(output, "<SignatureContext \n");
    } else {
	fprintf(output, "<VerificationContext \n");
    }
    switch(ctx->status) {
	case xmlDSigStatusUnknown:
	    fprintf(output, "status=\"unknown\" >\n");
	    break;
	case xmlDSigStatusSucceeded:
	    fprintf(output, "status=\"succeeded\" >\n");
	    break;
	case xmlDSigStatusInvalid:
	    fprintf(output, "status=\"invalid\" >\n");
	    break;
	case xmlDSigStatusFailed:
	    fprintf(output, "status=\"failed\" >\n");
	    break;
    }

    if(ctx->id != NULL) {
	fprintf(output, "<Id>%s</Id>\n", ctx->id);
    }

    fprintf(output, "<KeyInfoReadCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(ctx->keyInfoReadCtx), output);
    fprintf(output, "</KeyInfoReadCtx>\n");

    fprintf(output, "<KeyInfoWriteCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(ctx->keyInfoWriteCtx), output);
    fprintf(output, "</KeyInfoWriteCtx>\n");

    xmlSecTransformCtxDebugXmlDump(&(ctx->signTransformCtx), output);

    if((ctx->result != NULL) && 
       (xmlSecBufferGetData(ctx->result) != NULL)) {

	fprintf(output, "<Result>");
	fwrite(xmlSecBufferGetData(ctx->result), 
	       xmlSecBufferGetSize(ctx->result), 1,
	       output);
	fprintf(output, "</Result>\n");
    } else {
	fprintf(output, "<Result size=\"%d\" />\n",
	       xmlSecBufferGetSize(ctx->result));
    }

    /* todo: preSignMemBufMethod */
    /* todo: references and manifests */
    /* todo: sign key */

    if(ctx->sign) {    
	fprintf(output, "</SignatureContext>\n");
    } else {
	fprintf(output, "</VerificationContext>\n");
    }
}

/**************************************************************************
 *
 * xmlSecDSigReferenceCtx
 *
 *************************************************************************/

/**************************************************************************
 *
 * xmlSecDSigReferenceCtxListKlass
 *
 *************************************************************************/
static xmlSecPtrListKlass xmlSecDSigReferenceCtxListKlass = {
    BAD_CAST "dsig-reference-list",
    NULL,					/* xmlSecPtrDuplicateItemMethod duplicateItem; */
    NULL,					/* xmlSecPtrDestroyItemMethod destroyItem; */
    NULL,					/* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    NULL,					/* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

xmlSecPtrListId 
xmlSecDSigReferenceCtxListGetKlass(void) {
    return(&xmlSecDSigReferenceCtxListKlass);
}

/* TODO: destroy/print-debug */
#endif /* XMLSEC_NO_XMLDSIG */

