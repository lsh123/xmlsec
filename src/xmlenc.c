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

static int 	xmlSecEncCtxEncDataNodeRead		(xmlSecEncCtxPtr ctx, 
							 xmlNodePtr node);
static int 	xmlSecEncCtxCipherDataNodeRead		(xmlSecEncCtxPtr ctx, 
							 xmlNodePtr node);
static int 	xmlSecEncCtxCipherReferenceNodeRead	(xmlSecEncCtxPtr ctx, 
							 xmlNodePtr node);



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

    if(ctx->encKey != NULL) {
	xmlSecKeyDestroy(ctx->encKey);
    }
    if(ctx->id != NULL) {
	xmlFree(ctx->id);
    }	
    if(ctx->type != NULL) {
	xmlFree(ctx->type);
    }
    if(ctx->mimeType != NULL) {
	xmlFree(ctx->mimeType);
    }
    if(ctx->encoding != NULL) {
	xmlFree(ctx->encoding);
    }
    
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
    xmlChar* data = NULL;
    size_t dataSize = 0;
    int ret;
    
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->encResult == NULL, NULL);
    xmlSecAssert2(node != NULL, NULL);
    
    ctx->encrypt = 0;
    ret = xmlSecEncCtxEncDataNodeRead(ctx, node);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncCtxEncDataNodeRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }

    if(ctx->cipherValueNode != NULL) {
	data = xmlNodeGetContent(ctx->cipherValueNode);
	if(data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlNodeGetContent",
			XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(ctx->cipherValueNode)));
	    return(NULL);
	}	
	dataSize = xmlStrlen(data);
    }
    
    /* finaly decrypt the data */
    ctx->encResult = xmlSecTransformCtxExecute(&(ctx->transformCtx), node->doc, 
					       data, dataSize);
    if(ctx->encResult == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncCtxEncDataNodeRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }
    
    return(ctx->encResult);
}

static int 
xmlSecEncCtxEncDataNodeRead(xmlSecEncCtxPtr ctx, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    /* first read node data */
    xmlSecAssert2(ctx->id == NULL, -1);
    xmlSecAssert2(ctx->type == NULL, -1);
    xmlSecAssert2(ctx->mimeType == NULL, -1);
    xmlSecAssert2(ctx->encoding == NULL, -1);
    ctx->id = xmlGetProp(node, xmlSecAttrId);
    ctx->type = xmlGetProp(node, xmlSecAttrType);
    ctx->mimeType = xmlGetProp(node, xmlSecAttrMimeType);
    ctx->encoding = xmlGetProp(node, xmlSecAttrEncoding);    
    cur = xmlSecGetNextElementNode(node->children);
    
    /* first node is optional EncryptionMethod, we'll read it later */
    xmlSecAssert2(ctx->encMethodNode == NULL, -1);
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeEncryptionMethod, xmlSecEncNs))) {
	ctx->encMethodNode = cur;
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next node is optional KeyInfo, we'll process it later */
    xmlSecAssert2(ctx->keyInfoNode == NULL, -1);
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeKeyInfo, xmlSecDSigNs))) {
	ctx->keyInfoNode = cur;
	cur = xmlSecGetNextElementNode(cur->next);
    }    

    /* next is required CipherData node */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeCipherData, xmlSecEncNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeCipherData));
	return(-1);
    }
    ret = xmlSecEncCtxCipherDataNodeRead(ctx, cur);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncCtxCipherDataNodeRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is optional EncryptionProperties node (we simply ignore it) */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeEncryptionProperties, xmlSecEncNs))) {
	cur = xmlSecGetNextElementNode(cur->next);
    }

    /* if there is something left than it's an error */
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    NULL,
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* now read the encryption method node */
    if((ctx->encMethod == NULL) && (ctx->encMethodNode != NULL)) {
	ctx->encMethod = xmlSecTransformCtxNodeRead(&(ctx->transformCtx), ctx->encMethodNode,
						xmlSecTransformUsageEncryptionMethod);
	if(ctx->encMethod == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    	NULL,
			"xmlSecTransformCtxNodeRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(ctx->encMethodNode)));
	    return(-1);	    
	}	
    } else if(ctx->encMethod != NULL) {
	ret = xmlSecTransformCtxAppend(&(ctx->transformCtx), ctx->encMethod);
	if(ret < 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCtxAppend",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    } else {
	/* TODO: add default global enc method */
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "encryption method not specified");
	return(-1);
    }
    ctx->encMethod->encode = ctx->encrypt;
    
    /* we have encryption method, find key */
    if((ctx->encKey == NULL) && (ctx->keyInfoNode != NULL) && (ctx->keyInfoCtx.keysMngr->getKey != NULL)) {
	ret = xmlSecTransformSetKeyReq(ctx->encMethod, &(ctx->keyInfoCtx.keyReq));
	if(ret < 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformSetKeyReq",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformGetName(ctx->encMethod)));
	    return(-1);
	}		
	ctx->encKey = (ctx->keyInfoCtx.keysMngr->getKey)(ctx->keyInfoNode, &(ctx->keyInfoCtx));
    }
    if(ctx->encKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_KEY_NOT_FOUND,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    /* finally set the key to the transform */
    ret = xmlSecTransformSetKey(ctx->encMethod, ctx->encKey);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformSetKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(ctx->encMethod)));
	return(-1);
    }
    
    return(0);
}

static int 
xmlSecEncCtxCipherDataNodeRead(xmlSecEncCtxPtr ctx, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    cur = xmlSecGetNextElementNode(node->children);
    
    /* we either have CipherValue or CipherReference node  */
    xmlSecAssert2(ctx->cipherValueNode == NULL, -1);
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeCipherValue, xmlSecEncNs))) {
	xmlSecTransformPtr base64Decode;
	
	/* we need to add base64 decode transform */
	base64Decode = xmlSecTransformCtxCreateAndPrepend(&(ctx->transformCtx), xmlSecTransformBase64Id);
	if(base64Decode == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCtxCreateAndPrepend",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	ctx->cipherValueNode = cur;
        cur = xmlSecGetNextElementNode(cur->next);
    } else if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeCipherReference, xmlSecEncNs))) {
	ret = xmlSecEncCtxCipherReferenceNodeRead(ctx, cur);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    	NULL,
			"xmlSecEncCtxCipherReferenceNodeRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(cur)));
	    return(-1);	    
	}	
        cur = xmlSecGetNextElementNode(cur->next);
    }
    
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

static int 
xmlSecEncCtxCipherReferenceNodeRead(xmlSecEncCtxPtr ctx, xmlNodePtr node) {
    xmlNodePtr cur;
    xmlChar* uri;
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    /* first read the optional uri attr */
    uri = xmlGetProp(node, xmlSecAttrURI);
    if(uri != NULL) {
	ret = xmlSecTransformCtxSetUri(&(ctx->transformCtx), uri);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    	NULL,
			"xmlSecTransformCtxSetUri",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"uri=%s",
			xmlSecErrorsSafeString(uri));
	    xmlFree(uri);
	    return(-1);	    
	}		
	xmlFree(uri);
    }    
    cur = xmlSecGetNextElementNode(node->children);
    
    /* the only one node is optional Transforms node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeTransforms, xmlSecDSigNs))) {
	ret = xmlSecTransformCtxNodesListRead(&(ctx->transformCtx), cur,
				    xmlSecTransformUsageEncryptionMethod);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    	NULL,
			"xmlSecTransformCtxNodesListRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(ctx->encMethodNode)));
	    return(-1);	    
	}	
        cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* if there is something left than it's an error */
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    NULL,
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
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
    
    if(ctx->encResult != NULL) {
	fprintf(output, "== Result - start buffer:\n");
	fwrite(xmlSecBufferGetData(ctx->encResult), 
	       xmlSecBufferGetSize(ctx->encResult), 1,
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

    if(ctx->encResult != NULL) {
	fprintf(output, "<Result>");
	fwrite(xmlSecBufferGetData(ctx->encResult), 
	       xmlSecBufferGetSize(ctx->encResult), 1,
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

