/** 
 * XMLSec library
 *
 * XML Parser transform
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/parser.h>
#include <xmlsec/errors.h>

/**************************************************************************
 *
 * XML Parser transform 
 *
 *************************************************************************/
static int xmlSecTransformXmlParserPushBin			(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
								 int final,
							         xmlSecTransformCtxPtr transformCtx);
static int xmlSecTransformXmlParserPopXml			(xmlSecTransformPtr transform, 
								 xmlSecNodeSetPtr* nodes,
								 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecTransformXmlParserKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    sizeof(xmlSecTransform),		/* size_t objSize */

    BAD_CAST "xml-parser",
    xmlSecTransformTypeXml,		/* xmlSecTransformType type; */
    xmlSecTransformUsageDSigTransform,	/* xmlSecTransformUsage	usage; */
    NULL,				/* const xmlChar *href; */
    
    NULL,				/* xmlSecTransformInitializeMethod initialize; */
    NULL,				/* xmlSecTransformFinalizeMethod finalize; */
    NULL,				/* xmlSecTransformNodeReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,	/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformXmlParserPushBin,	/* xmlSecTransformPushBinMethod pushBin; */
    NULL,				/* xmlSecTransformPopBinMethod popBin; */
    NULL,				/* xmlSecTransformPushXmlMethod pushXml; */
    xmlSecTransformXmlParserPopXml,	/* xmlSecTransformPopXmlMethod popXml; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */

    NULL,				/* xmlSecTransformExecuteMethod executeXml; */
    NULL,				/* xmlSecTransformExecuteC14NMethod executeC14N; */
};

/**
 * xmlSecTransformXmlParserGetKlass:
 *
 */
xmlSecTransformId 
xmlSecTransformXmlParserGetKlass(void) {
    return(&xmlSecTransformXmlParserKlass);
}


static int 
xmlSecTransformXmlParserPushBin(xmlSecTransformPtr transform, const unsigned char* data,
				size_t dataSize, int final, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr in;
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXmlParserId), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    
    /* check/update current transform status */
    if(transform->status == xmlSecTransformStatusNone) {
	transform->status = xmlSecTransformStatusWorking;
    } else if(transform->status == xmlSecTransformStatusFinished) {
	/* the only way we can get here is if there is no input */
	xmlSecAssert2(xmlSecBufferGetSize(in) == 0, -1);
    } else if(transform->status != xmlSecTransformStatusWorking) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_STATUS,
		    "status=%d", transform->status);
	return(-1);
    }
    xmlSecAssert2(transform->status == xmlSecTransformStatusWorking, -1);
    
    /* push data to the input buffer */
    in = &(transform->inBuf);
    if((data != NULL) && (dataSize > 0)) {
	ret = xmlSecBufferAppend(in, data, dataSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferAppend",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", dataSize);
	    return(-1);
	}	
    }    
    
    /* time to parse the input and push to next in the chain */
    if(final != 0) {
	xmlDocPtr doc;
	
	if(xmlSecBufferGetSize(in) == 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			NULL,
			XMLSEC_ERRORS_R_INVALID_DATA,
			"size=0");
	    return(-1);
	}
	xmlSecAssert2(xmlSecBufferGetData(in) != NULL, -1);
	xmlSecAssert2(transform->outNodes == NULL, -1);
	    
	doc = xmlSecParseMemory(xmlSecBufferGetData(in), xmlSecBufferGetSize(in), 1);
	if(doc == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecParseMemory",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", xmlSecBufferGetSize(in));
	    return(-1);
	} 	
	xmlSecBufferEmpty(in); /* cleanup memory asap */
	
	transform->outNodes = xmlSecNodeSetCreate(doc, NULL, xmlSecNodeSetTree);
	if(transform->outNodes == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecNodeSetCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlFreeDoc(doc);
	    return(-1);
	}	
	xmlSecNodeSetDocDestroy(transform->outNodes); /* this node set "owns" the doc pointer */
	
	/* push result to the next transform (if exist) */
	if(transform->next != NULL) {
	    ret = xmlSecTransformPushXml(transform->next, transform->outNodes, transformCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecTransformPushXml",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	}        
	
	transform->status = xmlSecTransformStatusFinished;
    }

    return(0);
}

static int 
xmlSecTransformXmlParserPopXml(xmlSecTransformPtr transform, xmlSecNodeSetPtr* nodes,
			       xmlSecTransformCtxPtr transformCtx) {
    xmlParserInputBufferPtr buf;
    xmlParserInputPtr input;
    xmlParserCtxtPtr ctxt;
    xmlDocPtr doc;
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXmlParserId), -1);
    xmlSecAssert2(nodes != NULL, -1);    
    xmlSecAssert2(transformCtx != NULL, -1);

    /* check/update current transform status */
    switch(transform->status) {
    case xmlSecTransformStatusNone:
	transform->status = xmlSecTransformStatusWorking;
	break;
    case xmlSecTransformStatusWorking:
	/* just do nothing */
	break;
    case xmlSecTransformStatusFinished:
	(*nodes) = NULL;
	return(0);
    default:
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_STATUS,
		    "status=%d", transform->status);
	return(-1);
    }
    xmlSecAssert2(transform->status == xmlSecTransformStatusWorking, -1);
    
    /* prepare parser context */
    if(transform->prev == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "prev transform is null");
	return(-1);
    }
    
    buf = xmlSecTransformCreateInputBuffer(transform->prev, transformCtx);
    if(buf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecTransformCreateInputBuffer",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlNewParserCtxt",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFreeParserInputBuffer(buf);
	return(-1);
    }
    
    input = xmlNewIOInputStream(ctxt, buf, XML_CHAR_ENCODING_NONE);
    if(input == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlNewParserCtxt",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFreeParserCtxt(ctxt);
	xmlFreeParserInputBuffer(buf);
	return(-1);
    }
    
    ret = inputPush(ctxt, input);
    if(input == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "inputPush",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFreeInputStream(input);
	xmlFreeParserCtxt(ctxt);
	return(-1);
    }

    /* required for c14n! */
    ctxt->loadsubset = XML_DETECT_IDS | XML_COMPLETE_ATTRS; 
    ctxt->replaceEntities = 1;

    /* finaly do the parsing */
    ret = xmlParseDocument(ctxt);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlParseDocument",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	if(ctxt->myDoc != NULL) {
	    xmlFreeDoc(ctxt->myDoc);
	    ctxt->myDoc = NULL;
	}
	xmlFreeParserCtxt(ctxt);
	return(-1);
    }
    
    /* remember the result and free parsing context */
    doc = ctxt->myDoc;
    ctxt->myDoc = NULL;
    xmlFreeParserCtxt(ctxt);    

    /* return result to the caller */
    (*nodes) = xmlSecNodeSetCreate(doc, NULL, xmlSecNodeSetTree);
    if((*nodes) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecNodeSetCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFreeDoc(doc);
	return(-1);
    }	
    xmlSecNodeSetDocDestroy((*nodes)); /* this node set "owns" the doc pointer */
    transform->status = xmlSecTransformStatusFinished;
    return(0);
}

/**************************************************************************
 *
 * XML Parser functions
 *
 *************************************************************************/
typedef struct _xmlSecExtMemoryParserCtx {
    const unsigned char 	*prefix; 
    size_t 			prefixSize;
    const unsigned char 	*buffer;
    size_t			bufferSize;
    const unsigned char 	*postfix;
    size_t 			postfixSize;
} xmlSecExtMemoryParserCtx, *xmlSecExtMemoryParserCtxPtr;

/** 
 * xmlSecParseFile:
 * @filename: the filename.
 *
 * Loads XML Doc from file @filename. We need a special version because of 
 * c14n issue. The code is copied from xmlSAXParseFileWithData() function.
 *
 * Returns pointer to the loaded XML document or NULL if an error occurs.
 */
xmlDocPtr
xmlSecParseFile(const char *filename) {
    xmlDocPtr ret;
    xmlParserCtxtPtr ctxt;
    char *directory = NULL;
    
    xmlSecAssert2(filename != NULL, NULL);

    xmlInitParser();
    ctxt = xmlCreateFileParserCtxt(filename);
    if (ctxt == NULL) {
	return(NULL);
    }

    /* todo: set directories from current doc? */    
    if ((ctxt->directory == NULL) && (directory == NULL))
        directory = xmlParserGetDirectory(filename);
    if ((ctxt->directory == NULL) && (directory != NULL))
        ctxt->directory = (char *) xmlStrdup((xmlChar *) directory);

    /* required for c14n! */
    ctxt->loadsubset = XML_DETECT_IDS | XML_COMPLETE_ATTRS; 
    ctxt->replaceEntities = 1;
    
    xmlParseDocument(ctxt);

    if(ctxt->wellFormed) { 
	ret = ctxt->myDoc;
    } else {
       ret = NULL;
       xmlFreeDoc(ctxt->myDoc);
       ctxt->myDoc = NULL;
    }
    xmlFreeParserCtxt(ctxt);    
    return(ret);
    
}

static int 
xmlSecExtMemoryParserRead(void * context, char * buffer, int len) {
    xmlSecExtMemoryParserCtxPtr ctx;
    size_t size;

    xmlSecAssert2(context != NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(len > 0, -1);
        
    ctx = (xmlSecExtMemoryParserCtxPtr)context;
    if((ctx->prefix != NULL) && (ctx->prefixSize > 0)) {
	size = (ctx->prefixSize < (size_t)len) ? ctx->prefixSize : (size_t)len; 
	memcpy(buffer, ctx->prefix, size);
	ctx->prefix += size;
	ctx->prefixSize -= size;
	return(size);
    } else if((ctx->buffer != NULL) && (ctx->bufferSize > 0)) {
	size = (ctx->bufferSize < (size_t)len) ? ctx->bufferSize : (size_t)len; 
	memcpy(buffer, ctx->buffer, size);
	ctx->buffer += size;
	ctx->bufferSize -= size;
	return(size);
    } else if((ctx->postfix != NULL) && (ctx->postfixSize > 0)) {
	size = (ctx->postfixSize < (size_t)len) ? ctx->postfixSize : (size_t)len; 
	memcpy(buffer, ctx->postfix, size);
	ctx->postfix += size;
	ctx->postfixSize -= size;
	return(size);
    }
    return(0);
}

/**
 * xmlSecParseMemoryExt:
 * @prefix: the first part of the input.
 * @prefixSize: the size of the first part of the input.
 * @buffer: the second part of the input.
 * @bufferSize: the size of the second part of the input.
 * @postfix: the third part of the input.
 * @postfixSize: the size of the third part of the input.
 *
 * Loads XML Doc from 3 chunks of memory: @prefix, @buffer and @postfix. '
 *
 * Returns pointer to the loaded XML document or NULL if an error occurs.
 */
xmlDocPtr
xmlSecParseMemoryExt(const unsigned char *prefix, size_t prefixSize,
		     const unsigned char *buffer, size_t bufferSize, 
		     const unsigned char *postfix, size_t postfixSize) {
    xmlSecExtMemoryParserCtx extCtx;
    xmlDocPtr ret;
    xmlParserCtxtPtr ctxt;
    
    xmlSecAssert2(buffer != NULL, NULL);

    extCtx.prefix = prefix;
    extCtx.prefixSize = prefixSize;
    extCtx.buffer = buffer;
    extCtx.bufferSize = bufferSize;
    extCtx.postfix = postfix;
    extCtx.postfixSize = postfixSize;
        
    
    ctxt = xmlCreateIOParserCtxt(NULL, NULL, xmlSecExtMemoryParserRead, 
				 NULL, &extCtx, XML_CHAR_ENCODING_NONE);
    if (ctxt == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlCreateIOParserCtxt",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }

    /* required for c14n! */
    ctxt->loadsubset = XML_DETECT_IDS | XML_COMPLETE_ATTRS; 
    ctxt->replaceEntities = 1;

    xmlParseDocument(ctxt);
    ret = ctxt->myDoc; 
    xmlFreeParserCtxt(ctxt);    
    return(ret);
}


/**
 * xmlSecParseMemory:
 * @buffer: the input buffer.
 * @size: the input buffer size.
 * @recovery: the flag.
 *
 * Loads XML Doc from memory. We need a special version because of 
 * c14n issue. The code is copied from xmlSAXParseMemory() function.
 *
 * Returns pointer to the loaded XML document or NULL if an error occurs.
 */
xmlDocPtr
xmlSecParseMemory(const unsigned char *buffer, size_t size, int recovery) {
    xmlDocPtr ret;
    xmlParserCtxtPtr ctxt;

    xmlSecAssert2(buffer != NULL, NULL);
    
    ctxt = xmlCreateMemoryParserCtxt((char*)buffer, size);
    if (ctxt == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlCreateMemoryParserCtxt",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }

    /* required for c14n! */
    ctxt->loadsubset = XML_DETECT_IDS | XML_COMPLETE_ATTRS; 
    ctxt->replaceEntities = 1;

    xmlParseDocument(ctxt);

    if((ctxt->wellFormed) || recovery) {
	ret = ctxt->myDoc; 
    } else {
       ret = NULL;
       xmlFreeDoc(ctxt->myDoc);
       ctxt->myDoc = NULL;
    }
    xmlFreeParserCtxt(ctxt);    
    return(ret);
}

