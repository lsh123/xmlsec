/** 
 * XMLSec library
 *
 * "XML Encryption" implementation
 *  http://www.w3.org/TR/xmlenc-core
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
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




xmlSecEncCtxPtr	
xmlSecEncCtxCreate(xmlSecKeysMngrPtr keysMngr) {
    xmlSecEncCtxPtr ctx;
    int ret;
    
    ctx = (xmlSecEncCtxPtr) xmlMalloc(sizeof(xmlSecEncCtx));
    if(ctx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecEncCtx)=%d", 
		    sizeof(xmlSecEncCtx));
	return(NULL);
    }
    
    ret = xmlSecEncCtxInitialize(ctx, keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecEncCtxDestroy(ctx);
	return(NULL);   
    }
    return(ctx);    
}

void  
xmlSecEncCtxDestroy(xmlSecEncCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);
    
    xmlSecEncCtxFinalize(ctx);
    xmlFree(ctx);
}

int 
xmlSecEncCtxInitialize(xmlSecEncCtxPtr ctx, xmlSecKeysMngrPtr keysMngr) {
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    
    memset(ctx, 0, sizeof(xmlSecEncCtx));

#ifdef TODO
    /* initialize key info */
    ret = xmlSecKeyInfoCtxInitialize(&(ctx->keyInfoCtx), keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyInfoCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }
#else /* TODO */
    ctx->keyInfoCtx.keysMngr = keysMngr;
#endif /* TODO */  

    /* initializes transforms ctx */
    ret = xmlSecTransformCtxInitialize(&(ctx->transformCtx));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }
    
    return(0);
}

void 
xmlSecEncCtxFinalize(xmlSecEncCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    xmlSecTransformCtxFinalize(&(ctx->transformCtx));
#ifdef TODO
    xmlSecKeyInfoCtxFinalize(&(ctx->keyInfoCtx));
#endif /* TODO */  

    memset(ctx, 0, sizeof(xmlSecEncCtx));
}

int 
xmlSecEncCtxDecrypt(xmlSecEncCtxPtr ctx, xmlNodePtr node) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* TODO: */
    return(0);
}

xmlSecBufferPtr
xmlSecEncCtxDecryptToBuffer(xmlSecEncCtxPtr ctx, xmlNodePtr node) {
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(node != NULL, NULL);
    
    /* TODO: */
    return(0);
}

void 
xmlSecEncCtxDebugDump(xmlSecEncCtxPtr ctx, FILE* output) {
    xmlSecAssert(ctx != NULL);

    if(ctx->encrypt) {    
        fprintf(output, "= ENCRYPTION CONTEXT\n");
    } else {
        fprintf(output, "= DECRYPTION CONTEXT (%s)\n",
	    (ctx->replaced) ? "replaced" : "not-replaced" );
    }
    if(ctx->id != NULL) {
	fprintf(output, "== Id: \"%s\"\n", ctx->id);
    }
    if(ctx->type != NULL) {
	fprintf(output, "== Type: \"%s\"\n", ctx->type);
    }
    if(ctx->mimeType != NULL) {
	fprintf(output, "== MimeType: \"%s\"\n", ctx->mimeType);
    }
    if(ctx->encoding != NULL) {
	fprintf(output, "== Encoding: \"%s\"\n", ctx->encoding);
    }
    
#ifdef TODO    
    xmlSecKeyInfoCtxDebugDump(&(ctx->keyInfoCtx), output);
#endif
    xmlSecTransformCtxDebugDump(&(ctx->transformCtx), output);
    
    if(ctx->encryptionResult != NULL) {
	fprintf(output, "== Result - start buffer:\n");
	fwrite(xmlSecBufferGetData(ctx->encryptionResult), 
	       xmlSecBufferGetSize(ctx->encryptionResult), 1,
	       output);
	fprintf(output, "\n== Result - end buffer\n");
    }
}

void 
xmlSecEncCtxDebugXmlDump(xmlSecEncCtxPtr ctx, FILE* output) {
    xmlSecAssert(ctx != NULL);

    if(ctx->encrypt) {    
        fprintf(output, "<EncryptionContext>\n");
    } else {
        fprintf(output, "<DecryptionContext type=\"%s\">\n",
	    (ctx->replaced) ? "replaced" : "not-replaced" );
    }
    if(ctx->id != NULL) {
	fprintf(output, "<Id>%s</Id>\n", ctx->id);
    }
    if(ctx->type != NULL) {
	fprintf(output, "<Type>%s</Type>\n", ctx->type);
    }
    if(ctx->mimeType != NULL) {
	fprintf(output, "<MimeType%s</MimeType>\n", ctx->mimeType);
    }
    if(ctx->encoding != NULL) {
	fprintf(output, "<Encoding>%s</Encoding>\n", ctx->encoding);
    }
#ifdef TODO    
    xmlSecKeyInfoCtxDebugXmlDump(&(ctx->keyInfoCtx), output);
#endif
    xmlSecTransformCtxDebugXmlDump(&(ctx->transformCtx), output);

    if(ctx->encryptionResult != NULL) {
	fprintf(output, "<Result>");
	fwrite(xmlSecBufferGetData(ctx->encryptionResult), 
	       xmlSecBufferGetSize(ctx->encryptionResult), 1,
	       output);
	fprintf(output, "</Result>\n");
    }	    

    if(ctx->encrypt) {    
        fprintf(output, "</EncryptionContext>\n");
    } else {
        fprintf(output, "</DecryptionContext>\n");
    }
}


#include "xmlenc-old.c"
#endif /* XMLSEC_NO_XMLENC */

