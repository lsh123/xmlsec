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
    xmlSecDSigCtxPtr dsigCtx;
    int ret;
    
    dsigCtx = (xmlSecDSigCtxPtr) xmlMalloc(sizeof(xmlSecDSigCtx));
    if(dsigCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecDSigCtx)=%d", 
		    sizeof(xmlSecDSigCtx));
	return(NULL);
    }
    
    ret = xmlSecDSigCtxInitialize(dsigCtx, keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecDSigCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecDSigCtxDestroy(dsigCtx);
	return(NULL);   
    }
    return(dsigCtx);    
}

void  
xmlSecDSigCtxDestroy(xmlSecDSigCtxPtr dsigCtx) {
    xmlSecAssert(dsigCtx != NULL);
    
    xmlSecDSigCtxFinalize(dsigCtx);
    xmlFree(dsigCtx);
}

int 
xmlSecDSigCtxInitialize(xmlSecDSigCtxPtr dsigCtx, xmlSecKeysMngrPtr keysMngr) {
    int ret;
    
    xmlSecAssert2(dsigCtx != NULL, -1);
    
    memset(dsigCtx, 0, sizeof(xmlSecDSigCtx));

    /* initialize key info */
    ret = xmlSecKeyInfoCtxInitialize(&(dsigCtx->keyInfoReadCtx), keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyInfoCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }
    dsigCtx->keyInfoReadCtx.mode = xmlSecKeyInfoModeRead;
    
    ret = xmlSecKeyInfoCtxInitialize(&(dsigCtx->keyInfoWriteCtx), keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyInfoCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }
    dsigCtx->keyInfoWriteCtx.mode = xmlSecKeyInfoModeWrite;
    /* it's not wise to write private key :) */
    dsigCtx->keyInfoWriteCtx.keyReq.keyType = xmlSecKeyDataTypePublic;

    /* initializes transforms dsigCtx */
    ret = xmlSecTransformCtxInitialize(&(dsigCtx->signTransformCtx));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }

    xmlSecPtrListInitialize(&(dsigCtx->references), xmlSecDSigReferenceCtxListId);
    xmlSecPtrListInitialize(&(dsigCtx->manifests), xmlSecDSigReferenceCtxListId);

    /* TODO: set other values */	    
    return(0);
}

void 
xmlSecDSigCtxFinalize(xmlSecDSigCtxPtr dsigCtx) {
    xmlSecAssert(dsigCtx != NULL);

    xmlSecTransformCtxFinalize(&(dsigCtx->signTransformCtx));
    xmlSecKeyInfoCtxFinalize(&(dsigCtx->keyInfoReadCtx));
    xmlSecKeyInfoCtxFinalize(&(dsigCtx->keyInfoWriteCtx));
    xmlSecPtrListFinalize(&(dsigCtx->references));
    xmlSecPtrListFinalize(&(dsigCtx->manifests));

    if((dsigCtx->dontDestroyC14NMethod != 0) && (dsigCtx->c14nMethod != NULL)) {
	xmlSecTransformDestroy(dsigCtx->c14nMethod, 1);
    }    
    if((dsigCtx->dontDestroySignMethod != 0) && (dsigCtx->signMethod != NULL)) {
	xmlSecTransformDestroy(dsigCtx->signMethod, 1);
    }    
    if(dsigCtx->signKey != NULL) {
	xmlSecKeyDestroy(dsigCtx->signKey);
    }
    if(dsigCtx->id != NULL) {
	xmlFree(dsigCtx->id);
    }	
    /* TODO: cleanup all */
    memset(dsigCtx, 0, sizeof(xmlSecDSigCtx));
}

int 
xmlSecDSigCtxSign(xmlSecDSigCtxPtr dsigCtx, xmlNodePtr tmpl) {
    int ret;
    
    xmlSecAssert2(dsigCtx != NULL, -1);
    xmlSecAssert2(dsigCtx->result == NULL, -1);
    xmlSecAssert2(tmpl != NULL, -1);

    /* TODO */
    return(0);    
}

int 
xmlSecDSigCtxVerify(xmlSecDSigCtxPtr dsigCtx, xmlNodePtr node) {
    int ret;
    
    xmlSecAssert2(dsigCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    return(0);
}

void 
xmlSecDSigCtxDebugDump(xmlSecDSigCtxPtr dsigCtx, FILE* output) {
    xmlSecAssert(dsigCtx != NULL);

    if(dsigCtx->sign) {    
	fprintf(output, "= SIGNATURE CONTEXT\n");
    } else {
	fprintf(output, "= VERIFICATION CONTEXT\n");
    }
    switch(dsigCtx->status) {
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
    if(dsigCtx->id != NULL) {
	fprintf(output, "== Id: \"%s\"\n", dsigCtx->id);
    }
    
    fprintf(output, "== Key Info Read Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(dsigCtx->keyInfoReadCtx), output);
    fprintf(output, "== Key Info Write Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(dsigCtx->keyInfoWriteCtx), output);

    xmlSecTransformCtxDebugDump(&(dsigCtx->signTransformCtx), output);
    
    if((dsigCtx->result != NULL) && 
       (xmlSecBufferGetData(dsigCtx->result) != NULL)) {

	fprintf(output, "== Result - start buffer:\n");
	fwrite(xmlSecBufferGetData(dsigCtx->result), 
	       xmlSecBufferGetSize(dsigCtx->result), 1,
	       output);
	fprintf(output, "\n== Result - end buffer\n");
    } else {
	fprintf(output, "== Result: %d bytes\n",
		xmlSecBufferGetSize(dsigCtx->result));
    }
    
    /* todo: preSignMemBufMethod */
    /* todo: references and manifests */
    /* todo: sign key */
}

void 
xmlSecDSigCtxDebugXmlDump(xmlSecDSigCtxPtr dsigCtx, FILE* output) {
    xmlSecAssert(dsigCtx != NULL);

    if(dsigCtx->sign) {    
	fprintf(output, "<SignatureContext \n");
    } else {
	fprintf(output, "<VerificationContext \n");
    }
    switch(dsigCtx->status) {
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

    if(dsigCtx->id != NULL) {
	fprintf(output, "<Id>%s</Id>\n", dsigCtx->id);
    }

    fprintf(output, "<KeyInfoReadCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(dsigCtx->keyInfoReadCtx), output);
    fprintf(output, "</KeyInfoReadCtx>\n");

    fprintf(output, "<KeyInfoWriteCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(dsigCtx->keyInfoWriteCtx), output);
    fprintf(output, "</KeyInfoWriteCtx>\n");

    xmlSecTransformCtxDebugXmlDump(&(dsigCtx->signTransformCtx), output);

    if((dsigCtx->result != NULL) && 
       (xmlSecBufferGetData(dsigCtx->result) != NULL)) {

	fprintf(output, "<Result>");
	fwrite(xmlSecBufferGetData(dsigCtx->result), 
	       xmlSecBufferGetSize(dsigCtx->result), 1,
	       output);
	fprintf(output, "</Result>\n");
    } else {
	fprintf(output, "<Result size=\"%d\" />\n",
	       xmlSecBufferGetSize(dsigCtx->result));
    }

    /* todo: preSignMemBufMethod */
    /* todo: references and manifests */
    /* todo: sign key */

    if(dsigCtx->sign) {    
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
xmlSecDSigReferenceCtxPtr	
xmlSecDSigReferenceCtxCreate(xmlSecDSigCtxPtr dsigCtx, xmlSecDSigReferenceOrigin origin) {
    xmlSecDSigReferenceCtxPtr dsigRefCtx;
    int ret;
    
    xmlSecAssert2(dsigCtx != NULL, NULL);
    
    dsigRefCtx = (xmlSecDSigReferenceCtxPtr) xmlMalloc(sizeof(xmlSecDSigReferenceCtx));
    if(dsigRefCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecDSigReferenceCtx)=%d", 
		    sizeof(xmlSecDSigReferenceCtx));
	return(NULL);
    }
    
    ret = xmlSecDSigReferenceCtxInitialize(dsigRefCtx, dsigCtx, origin);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecDSigReferenceCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecDSigReferenceCtxDestroy(dsigRefCtx);
	return(NULL);   
    }
    return(dsigRefCtx);    
}

void  
xmlSecDSigReferenceCtxDestroy(xmlSecDSigReferenceCtxPtr dsigRefCtx) {
    xmlSecAssert(dsigRefCtx != NULL);
    
    xmlSecDSigReferenceCtxFinalize(dsigRefCtx);
    xmlFree(dsigRefCtx);
}

int 
xmlSecDSigReferenceCtxInitialize(xmlSecDSigReferenceCtxPtr dsigRefCtx, xmlSecDSigCtxPtr dsigCtx,
				xmlSecDSigReferenceOrigin origin) {
    int ret;
    
    xmlSecAssert2(dsigCtx != NULL, -1);
    xmlSecAssert2(dsigRefCtx != NULL, -1);
    
    memset(dsigRefCtx, 0, sizeof(xmlSecDSigReferenceCtx));
    
    dsigRefCtx->dsigCtx = dsigCtx;
    dsigRefCtx->origin = origin;
    
    /* initializes transforms dsigRefCtx */
    ret = xmlSecTransformCtxInitialize(&(dsigRefCtx->digestTransformCtx));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }

    /* TODO: set other values */	    
    return(0);
}

void 
xmlSecDSigReferenceCtxFinalize(xmlSecDSigReferenceCtxPtr dsigRefCtx) {
    xmlSecAssert(dsigRefCtx != NULL);

    xmlSecTransformCtxFinalize(&(dsigRefCtx->digestTransformCtx));

    if(dsigRefCtx->c14nMethod != NULL) {
	xmlSecTransformDestroy(dsigRefCtx->c14nMethod, 1);
    }    
    if(dsigRefCtx->digestMethod != NULL) {
	xmlSecTransformDestroy(dsigRefCtx->digestMethod, 1);
    }    
    if(dsigRefCtx->id != NULL) {
	xmlFree(dsigRefCtx->id);
    }	
    if(dsigRefCtx->uri != NULL) {
	xmlFree(dsigRefCtx->uri);
    }	
    if(dsigRefCtx->type != NULL) {
	xmlFree(dsigRefCtx->type);
    }	
    /* TODO: cleanup all */
    memset(dsigRefCtx, 0, sizeof(xmlSecDSigReferenceCtx));
}

int 
xmlSecDSigReferenceCtxCalculate(xmlSecDSigReferenceCtxPtr dsigRefCtx, xmlNodePtr tmpl) {
    int ret;
    
    xmlSecAssert2(dsigRefCtx != NULL, -1);
    xmlSecAssert2(dsigRefCtx->dsigCtx != NULL, -1);
    xmlSecAssert2(dsigRefCtx->result == NULL, -1);
    xmlSecAssert2(tmpl != NULL, -1);

    /* TODO */
    return(0);    
}

int 
xmlSecDSigReferenceCtxVerify(xmlSecDSigReferenceCtxPtr dsigRefCtx, xmlNodePtr node) {
    int ret;
    
    xmlSecAssert2(dsigRefCtx != NULL, -1);
    xmlSecAssert2(dsigRefCtx->dsigCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    return(0);
}

void 
xmlSecDSigReferenceCtxDebugDump(xmlSecDSigReferenceCtxPtr dsigRefCtx, FILE* output) {
    xmlSecAssert(dsigRefCtx != NULL);
    xmlSecAssert(dsigRefCtx->dsigCtx != NULL);

    if(dsigRefCtx->dsigCtx->sign) {    
	fprintf(output, "= REFERENCE CALCULATION CONTEXT\n");
    } else {
	fprintf(output, "= REFERENCE VERIFICATION CONTEXT\n");
    }
    switch(dsigRefCtx->status) {
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
    if(dsigRefCtx->id != NULL) {
	fprintf(output, "== Id: \"%s\"\n", dsigRefCtx->id);
    }
    if(dsigRefCtx->uri != NULL) {
	fprintf(output, "== URI: \"%s\"\n", dsigRefCtx->uri);
    }
    if(dsigRefCtx->type != NULL) {
	fprintf(output, "== Type: \"%s\"\n", dsigRefCtx->type);
    }

    /* todo: digestMethod */
    /* todo: c14nMethod */

    xmlSecTransformCtxDebugDump(&(dsigRefCtx->digestTransformCtx), output);

    /* todo: preSignMemBufMethod */
    
    if((dsigRefCtx->result != NULL) && 
       (xmlSecBufferGetData(dsigRefCtx->result) != NULL)) {

	fprintf(output, "== Result - start buffer:\n");
	fwrite(xmlSecBufferGetData(dsigRefCtx->result), 
	       xmlSecBufferGetSize(dsigRefCtx->result), 1,
	       output);
	fprintf(output, "\n== Result - end buffer\n");
    } else {
	fprintf(output, "== Result: %d bytes\n",
		xmlSecBufferGetSize(dsigRefCtx->result));
    }
}

void 
xmlSecDSigReferenceCtxDebugXmlDump(xmlSecDSigReferenceCtxPtr dsigRefCtx, FILE* output) {
    xmlSecAssert(dsigRefCtx != NULL);
    xmlSecAssert(dsigRefCtx->dsigCtx != NULL);

    if(dsigRefCtx->dsigCtx->sign) {    
	fprintf(output, "<ReferenceCalculationContext \n");
    } else {
	fprintf(output, "<ReferenceVerificationContext \n");
    }
    switch(dsigRefCtx->status) {
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

    if(dsigRefCtx->id != NULL) {
	fprintf(output, "<Id>%s</Id>\n", dsigRefCtx->id);
    }
    if(dsigRefCtx->uri != NULL) {
	fprintf(output, "<URI>%s</URI>\n", dsigRefCtx->uri);
    }
    if(dsigRefCtx->type != NULL) {
	fprintf(output, "<Type>%s</Type>\n", dsigRefCtx->type);
    }

    /* todo: digestMethod */
    /* todo: c14nMethod */
    xmlSecTransformCtxDebugXmlDump(&(dsigRefCtx->digestTransformCtx), output);

    if((dsigRefCtx->result != NULL) && 
       (xmlSecBufferGetData(dsigRefCtx->result) != NULL)) {

	fprintf(output, "<Result>");
	fwrite(xmlSecBufferGetData(dsigRefCtx->result), 
	       xmlSecBufferGetSize(dsigRefCtx->result), 1,
	       output);
	fprintf(output, "</Result>\n");
    } else {
	fprintf(output, "<Result size=\"%d\" />\n",
	       xmlSecBufferGetSize(dsigRefCtx->result));
    }

    /* todo: preSignMemBufMethod */
    if(dsigRefCtx->dsigCtx->sign) {    
	fprintf(output, "</ReferenceCalculationContext>\n");
    } else {
	fprintf(output, "</ReferenceVerificationContext>\n");
    }
}


/**************************************************************************
 *
 * xmlSecDSigReferenceCtxListKlass
 *
 *************************************************************************/
static xmlSecPtrListKlass xmlSecDSigReferenceCtxListKlass = {
    BAD_CAST "dsig-reference-list",
    NULL,								/* xmlSecPtrDuplicateItemMethod duplicateItem; */
    (xmlSecPtrDestroyItemMethod)xmlSecDSigReferenceCtxDestroy,		/* xmlSecPtrDestroyItemMethod destroyItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecDSigReferenceCtxDebugDump,	/* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecDSigReferenceCtxDebugXmlDump,	/* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

xmlSecPtrListId 
xmlSecDSigReferenceCtxListGetKlass(void) {
    return(&xmlSecDSigReferenceCtxListKlass);
}

/* TODO: destroy/print-debug */
#endif /* XMLSEC_NO_XMLDSIG */

