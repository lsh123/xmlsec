/**		
 * XMLSec library
 *
 * Serializable Objects
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/serializable.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>


/*********************************************************************
 *
 * Serializable object
 *
 *********************************************************************/
xmlSecObjKlassPtr
xmlSecSObjKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecSObjKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecSObjKlass),
	    "xmlSecSObj",
	    NULL, 			/* xmlSecObjKlassInitMethod */
	    NULL,			/* xmlSecObjKlassFinalizeMethod */
	    
	    /* obj info */
	    sizeof(xmlSecSObj),
	    NULL,			/* xmlSecObjKlassConstructorMethod */
	    NULL,			/* xmlSecObjKlassDuplicatorMethod */
	    NULL			/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
				       &kklassInfo, xmlSecObjKlassId); 
    } 
    return(klass);   
}

int		
xmlSecSObjReadXml(xmlSecSObjPtr sobj, xmlSecObjPtr ctx, xmlNodePtr node) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(sobj);
    xmlSecSObjKlassPtr sobjKlass = xmlSecSObjKlassCast(klass);

    xmlSecAssert2(sobj != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(sobjKlass != NULL, -1);

    if(sobjKlass->readXml == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_OBJECT_FAILED,	
		    "readXml(\"%s\")", 
    		    xmlSecObjKlassGetKlassName(klass));
	return(-1);
    }
    return((sobjKlass->readXml)(sobj, ctx, node));
}

int
xmlSecSObjReadBinary(xmlSecSObjPtr sobj, xmlSecObjPtr ctx, 
		const unsigned char *buf, size_t size) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(sobj);
    xmlSecSObjKlassPtr sobjKlass = xmlSecSObjKlassCast(klass);

    xmlSecAssert2(sobj != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(sobjKlass != NULL, -1);

    if(sobjKlass->readBinary == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_OBJECT_FAILED,	
		    "readBinary(\"%s\")", 
    		    xmlSecObjKlassGetKlassName(klass));
	return(-1);
    }
    return((sobjKlass->readBinary)(sobj, ctx, buf, size));
}

int
xmlSecSObjWriteXml(xmlSecSObjPtr sobj, xmlSecObjPtr ctx, xmlNodePtr node) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(sobj);
    xmlSecSObjKlassPtr sobjKlass = xmlSecSObjKlassCast(klass);

    xmlSecAssert2(sobj != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(sobjKlass != NULL, -1);

    if(sobjKlass->writeXml == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_OBJECT_FAILED,	
		    "writeXml(\"%s\")", 
    		    xmlSecObjKlassGetKlassName(klass));
	return(-1);
    }
    return((sobjKlass->writeXml)(sobj, ctx, node));
}

int
xmlSecSObjWriteBinary(xmlSecSObjPtr sobj, xmlSecObjPtr ctx, xmlSecBufferPtr buf) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(sobj);
    xmlSecSObjKlassPtr sobjKlass = xmlSecSObjKlassCast(klass);

    xmlSecAssert2(sobj != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(sobjKlass != NULL, -1);

    if(sobjKlass->writeBinary == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_OBJECT_FAILED,	
		    "writeBinary(\"%s\")", 
    		    xmlSecObjKlassGetKlassName(klass));
	return(-1);
    }
    return((sobjKlass->writeBinary)(sobj, ctx, buf));
}

/*********************************************************************
 *
 * Binary BaseBuffer
 *
 *********************************************************************/
static void		xmlSecBaseBufferKlassInit	(xmlSecObjKlassPtr klass);
static int		xmlSecBaseBufferConstructor	(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr obj);
static int		xmlSecBaseBufferDuplicator	(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr dst, 
							 xmlSecObjPtr src);
static void		xmlSecBaseBufferDestructor	(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr dst);
static void		xmlSecBaseBufferDebugDump	(xmlSecObjPtr obj,
							 FILE* output,
							 size_t level);
static void		xmlSecBaseBufferDebugXmlDump	(xmlSecObjPtr obj,
							 FILE* output,
							 size_t level);

xmlSecObjKlassPtr
xmlSecBaseBufferKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecBaseBufferKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecBaseBufferKlass),
	    "xmlSecBaseBuffer",
	    xmlSecBaseBufferKlassInit, 	/* xmlSecObjKlassInitMethod */
	    NULL,			/* xmlSecObjKlassFinalizeMethod */
	    
	    /* obj info */
	    sizeof(xmlSecBaseBuffer),
	    xmlSecBaseBufferConstructor,	/* xmlSecObjKlassConstructorMethod */
	    xmlSecBaseBufferDuplicator,	/* xmlSecObjKlassDuplicatorMethod */
	    xmlSecBaseBufferDestructor,	/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
				       &kklassInfo, xmlSecSObjKlassId); 
    } 
    return(klass);   
}

xmlSecPtr
xmlSecBaseBufferGetData(xmlSecBaseBufferPtr baseBuffer, size_t pos) {
    xmlSecObjKlassPtr objKlass = xmlSecObjGetKlass(xmlSecObjCast(baseBuffer));
    xmlSecBaseBufferKlassPtr baseBufferKlass = xmlSecBaseBufferKlassCast(objKlass);
    
    xmlSecAssert2(baseBuffer != NULL, NULL);
    xmlSecAssert2(baseBufferKlass != NULL, NULL);
    xmlSecAssert2(baseBufferKlass->itemSize > 0, NULL);
    
    if(pos < baseBuffer->size) {
	xmlSecAssert2(baseBuffer->data != NULL, NULL);

	return (baseBuffer->data + pos * baseBufferKlass->itemSize);
    }
    return(NULL);
}

size_t
xmlSecBaseBufferGetSize(xmlSecBaseBufferPtr baseBuffer) {
    xmlSecAssert2(baseBuffer != NULL, 0);
    
    return(baseBuffer->size);
}

size_t
xmlSecBaseBufferGetMaxSize(xmlSecBaseBufferPtr baseBuffer) {
    xmlSecAssert2(baseBuffer != NULL, 0);
    
    return(baseBuffer->maxSize);
}


int
xmlSecBaseBufferInsert(xmlSecBaseBufferPtr baseBuffer, size_t pos, size_t size) {
    xmlSecObjKlassPtr objKlass = xmlSecObjGetKlass(xmlSecObjCast(baseBuffer));
    xmlSecBaseBufferKlassPtr baseBufferKlass = xmlSecBaseBufferKlassCast(objKlass);
    int ret;
    
    xmlSecAssert2(baseBuffer != NULL, -1);
    xmlSecAssert2(baseBufferKlass != NULL, -1);
    xmlSecAssert2(baseBufferKlass->itemSize > 0, -1);

    ret = xmlSecBaseBufferAllocate(baseBuffer, baseBuffer->size + size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecBaseBufferAllocate(size=%d)", baseBuffer->size + size);
	return(-1);			
    }
    xmlSecAssert2(baseBuffer->maxSize >= baseBuffer->size + size, -1);
    
    if(pos < baseBuffer->size) {
	XMLSEC_BYTE* insertPos;
	XMLSEC_BYTE* movePos;
	size_t moveSize;

	xmlSecAssert2(baseBuffer->data != NULL, -1);
	
	insertPos = baseBuffer->data + pos * baseBufferKlass->itemSize;
	movePos = baseBuffer->data + (pos + size) * baseBufferKlass->itemSize;
	moveSize = (baseBuffer->size - pos) * baseBufferKlass->itemSize;
	
	memmove(movePos, insertPos, moveSize);
    }
    baseBuffer->size += size;
    return(0);    
}

int
xmlSecBaseBufferRemove(xmlSecBaseBufferPtr baseBuffer, size_t pos, size_t size) {
    xmlSecObjKlassPtr objKlass = xmlSecObjGetKlass(xmlSecObjCast(baseBuffer));
    xmlSecBaseBufferKlassPtr baseBufferKlass = xmlSecBaseBufferKlassCast(objKlass);
    
    xmlSecAssert2(baseBuffer != NULL, -1);
    xmlSecAssert2(pos <= baseBuffer->size, -1);
    xmlSecAssert2(baseBufferKlass != NULL, -1);
    xmlSecAssert2(baseBufferKlass->itemSize > 0, -1);
	
    if(pos + size < baseBuffer->size) {
	XMLSEC_BYTE* removePos;
	XMLSEC_BYTE* movePos;
	size_t moveSize;
	
	xmlSecAssert2(baseBuffer->data != NULL, -1);
	
	removePos = baseBuffer->data + pos * baseBufferKlass->itemSize;
	movePos = baseBuffer->data + (pos + size) * baseBufferKlass->itemSize;
	moveSize = (baseBuffer->size - pos - size) * baseBufferKlass->itemSize;
	
	memmove(removePos, movePos, moveSize);
	baseBuffer->size -= size;
    } else {
	baseBuffer->size = pos;    
    }
    
    return(0);
}

void
xmlSecBaseBufferEmpty(xmlSecBaseBufferPtr baseBuffer) {
    xmlSecAssert(baseBuffer != NULL);

    if(baseBuffer->maxSize > 0) {
	xmlSecAssert(baseBuffer->data != NULL);
	memset(baseBuffer->data, 0, baseBuffer->maxSize);
    }
    baseBuffer->size = 0;
}

int
xmlSecBaseBufferAllocate(xmlSecBaseBufferPtr baseBuffer, size_t size) {
    xmlSecObjKlassPtr objKlass = xmlSecObjGetKlass(xmlSecObjCast(baseBuffer));
    xmlSecBaseBufferKlassPtr baseBufferKlass = xmlSecBaseBufferKlassCast(objKlass);
    void* p;
    
    xmlSecAssert2(baseBuffer != NULL, -1);
    xmlSecAssert2(baseBufferKlass != NULL, -1);
    xmlSecAssert2(baseBufferKlass->itemSize > 0, -1);
    
    if(size <= baseBuffer->maxSize) {
	return(0);
    }
    
    p = xmlRealloc(baseBuffer->data, size * baseBufferKlass->itemSize);
    if(p == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", size);
	return(-1);
    }
    
    baseBuffer->data = (XMLSEC_BYTE*)p;
    baseBuffer->maxSize = size;
    return(0);
}

static void
xmlSecBaseBufferKlassInit(xmlSecObjKlassPtr klass) {
    xmlSecBaseBufferKlassPtr baseBufferKlass = (xmlSecBaseBufferKlassPtr)klass;

    xmlSecAssert(sizeof(XMLSEC_BYTE) == 1);
    xmlSecAssert(klass != NULL);
    xmlSecAssert(baseBufferKlass != NULL);
    
    klass->debugDump 		= xmlSecBaseBufferDebugDump;
    klass->debugXmlDump 	= xmlSecBaseBufferDebugXmlDump;
    baseBufferKlass->itemSize	= 0;
}

static int
xmlSecBaseBufferConstructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr obj) {
    xmlSecBaseBufferPtr baseBuffer = xmlSecBaseBufferCast(obj);

    xmlSecAssert2(baseBuffer != NULL, -1);

    baseBuffer->data 	= NULL;
    baseBuffer->size	= 0;
    baseBuffer->maxSize= 0;
    
    return(0);
}

static int
xmlSecBaseBufferDuplicator(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr dst, xmlSecObjPtr src) {
    xmlSecBaseBufferKlassPtr baseBufferKlass = xmlSecBaseBufferKlassCast(klass);
    xmlSecBaseBufferPtr baseBufferDst = xmlSecBaseBufferCast(dst);
    xmlSecBaseBufferPtr baseBufferSrc = xmlSecBaseBufferCast(src);
    size_t sizeSrc;
    
    xmlSecAssert2(baseBufferKlass != NULL, -1);
    xmlSecAssert2(baseBufferKlass->itemSize > 0, -1);
    xmlSecAssert2(baseBufferDst != NULL, -1);
    xmlSecAssert2(baseBufferSrc != NULL, -1);
    
    sizeSrc = xmlSecBaseBufferGetSize(baseBufferSrc);
    if(sizeSrc > 0) {
	int ret;
	
	ret = xmlSecBaseBufferAllocate(baseBufferDst, sizeSrc);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
    			XMLSEC_ERRORS_R_XMLSEC_FAILED,	
			"xmlSecBaseBufferAllocate(%d) - %d", sizeSrc, ret);
	    return(-1);
	} 
    
	xmlSecAssert2(baseBufferSrc->data != NULL, -1);
	xmlSecAssert2(baseBufferDst->data != NULL, -1);

	memcpy(baseBufferDst->data, baseBufferSrc->data, sizeSrc * baseBufferKlass->itemSize);
	baseBufferDst->size = baseBufferSrc->size;
    } 
    return(0);
}

static void
xmlSecBaseBufferDestructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
				    xmlSecObjPtr obj) {
    xmlSecBaseBufferPtr baseBuffer = xmlSecBaseBufferCast(obj);

    xmlSecAssert(baseBuffer != NULL);

    xmlSecBaseBufferEmpty(baseBuffer);
    if(baseBuffer->data != NULL) {
	xmlFree(baseBuffer->data);
    }
    baseBuffer->data 	= NULL;
    baseBuffer->size	= 0;
    baseBuffer->maxSize= 0;
}

static void
xmlSecBaseBufferDebugDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecObjKlassPtr objKlass = xmlSecObjGetKlass(obj);
    xmlSecBaseBufferKlassPtr baseBufferKlass = xmlSecBaseBufferKlassCast(objKlass);
    xmlSecBaseBufferPtr baseBuffer = xmlSecBaseBufferCast(obj);
    
    xmlSecAssert(baseBuffer != NULL);
    xmlSecAssert(baseBufferKlass != NULL);
    xmlSecAssert(baseBufferKlass->itemSize > 0);
    xmlSecAssert(output != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "base buffer size: %d\n", baseBuffer->size);
    xmlSecObjDebugIndent(output, level);
    fprintf(output, "base buffer max size: %d\n", baseBuffer->maxSize);
    xmlSecObjDebugIndent(output, level);
    fprintf(output, "base buffer item size: %d\n", baseBufferKlass->itemSize);
}

static void
xmlSecBaseBufferDebugXmlDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecObjKlassPtr objKlass = xmlSecObjGetKlass(obj);
    xmlSecBaseBufferKlassPtr baseBufferKlass = xmlSecBaseBufferKlassCast(objKlass);
    xmlSecBaseBufferPtr baseBuffer = xmlSecBaseBufferCast(obj);
    
    xmlSecAssert(baseBuffer != NULL);
    xmlSecAssert(baseBufferKlass != NULL);
    xmlSecAssert(baseBufferKlass->itemSize > 0);
    xmlSecAssert(output != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "<BaseBuffer size=\"%d\" maxSize=\"%d\" itemSize=\"%d\" />\n", 
	    baseBuffer->size, baseBuffer->maxSize, baseBufferKlass->itemSize);
}



/*********************************************************************
 *
 * Binary Buffer
 *
 *********************************************************************/
static void		xmlSecBufferKlassInit		(xmlSecObjKlassPtr klass);
static void		xmlSecBufferDebugDump		(xmlSecObjPtr obj,
							 FILE* output,
							 size_t level);
static void		xmlSecBufferDebugXmlDump	(xmlSecObjPtr obj,
							 FILE* output,
							 size_t level);
static int		xmlSecBufferReadXml		(xmlSecSObjPtr sobj, 
							 xmlSecObjPtr ctx, 
							 xmlNodePtr node);
static int		xmlSecBufferWriteXml		(xmlSecSObjPtr sobj, 
							 xmlSecObjPtr ctx, 
							 xmlNodePtr node);
static int		xmlSecBufferReadBinary		(xmlSecSObjPtr sobj, 
							 xmlSecObjPtr ctx, 
							 const unsigned char *data, 
							 size_t size);
static int		xmlSecBufferWriteBinary		(xmlSecSObjPtr sobj, 
							 xmlSecObjPtr ctx, 
							 xmlSecBufferPtr buf);

xmlSecObjKlassPtr
xmlSecBufferKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecBufferKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecBufferKlass),
	    "xmlSecBuffer",
	    xmlSecBufferKlassInit, 	/* xmlSecObjKlassInitMethod */
	    NULL,			/* xmlSecObjKlassFinalizeMethod */
	    
	    /* obj info */
	    sizeof(xmlSecBuffer),
	    NULL,			/* xmlSecObjKlassConstructorMethod */
	    NULL,			/* xmlSecObjKlassDuplicatorMethod */
	    NULL,			/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
				       &kklassInfo, xmlSecBaseBufferKlassId); 
    } 
    return(klass);   
}

unsigned char*
xmlSecBufferGetBuffer(xmlSecBufferPtr buf) {
    xmlSecBaseBufferPtr baseBuffer = xmlSecBaseBufferCast(buf);

    xmlSecAssert2(baseBuffer != NULL, NULL);
    
    return((unsigned char*)baseBuffer->data);
}

int
xmlSecBufferSet(xmlSecBufferPtr buf, const unsigned char* data, size_t size) {
    xmlSecBaseBufferPtr baseBuffer = xmlSecBaseBufferCast(buf);
    int ret;
    
    xmlSecAssert2(baseBuffer != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    
    ret = xmlSecBaseBufferAllocate(baseBuffer, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecBaseBufferAllocate(size=%d)", size);
	return(-1);
			
    }
    xmlSecAssert2(baseBuffer->data != NULL, -1);
    xmlSecAssert2(baseBuffer->maxSize >= size, -1);
    
    memcpy(baseBuffer->data, data, size);
    baseBuffer->size = size;
    return(0);
}

int
xmlSecBufferAppend(xmlSecBufferPtr buf, const unsigned char* data, size_t size) {
    xmlSecBaseBufferPtr baseBuffer = xmlSecBaseBufferCast(buf);

    xmlSecAssert2(baseBuffer != NULL, -1);
    
    return (xmlSecBufferInsert(buf, baseBuffer->size, data, size));
}

int
xmlSecBufferPrepend(xmlSecBufferPtr buf, const unsigned char* data, size_t size) {
    xmlSecAssert2(buf != NULL, -1);
    
    return (xmlSecBufferInsert(buf, 0, data, size));
}

int
xmlSecBufferInsert(xmlSecBufferPtr buf, size_t pos, const unsigned char* data, size_t size) {
    xmlSecBaseBufferPtr baseBuffer = xmlSecBaseBufferCast(buf);
    unsigned char* insertPos;
    int ret;
    
    xmlSecAssert2(baseBuffer != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    
    ret = xmlSecBaseBufferInsert(baseBuffer, pos, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecBaseBufferInsert(pos=%d, size=%d)", pos, size);
	return(-1);			
    }
    
    insertPos = (unsigned char*)xmlSecBaseBufferGetData(baseBuffer, pos);
    if(insertPos == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecBaseBufferGetData(pos=%d)", pos);
	return(-1);			
    }
    
    xmlSecAssert2(baseBuffer->size >= pos + size, -1);    
    memcpy(insertPos, data, size);
    return(0);    
}

void
xmlSecBufferRemove(xmlSecBufferPtr buf, size_t pos, size_t size) {
    xmlSecBaseBufferPtr baseBuffer = xmlSecBaseBufferCast(buf);
    int ret;
    
    xmlSecAssert(baseBuffer != NULL);
    
    ret = xmlSecBaseBufferInsert(baseBuffer, pos, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecBaseBufferRemove(pos=%d, size=%d)", pos, size);
	return;
    }
}

/* base 64 */
xmlChar*
xmlSecBufferBase64Encode(xmlSecBufferPtr buf, int columns) {
    xmlSecBaseBufferPtr baseBuffer = xmlSecBaseBufferCast(buf);

    xmlSecAssert2(baseBuffer != NULL, NULL);

    if(baseBuffer->size > 0) {
	xmlSecAssert2(baseBuffer->data != NULL, NULL);
	
	return(xmlSecBase64Encode(baseBuffer->data, baseBuffer->size, columns));
    }
    return(xmlStrdup(BAD_CAST ""));
}

int
xmlSecBufferBase64Decode(xmlSecBufferPtr buf, const xmlChar* str) {
    xmlSecBaseBufferPtr baseBuffer = xmlSecBaseBufferCast(buf);

    int ret;
    
    xmlSecAssert2(baseBuffer != NULL, -1);
    xmlSecAssert2(str != NULL, -1);

    ret = xmlSecBaseBufferAllocate(baseBuffer, xmlStrlen(str));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBaseBufferAllocate - %d", ret);
	return(-1);
    }
    
    ret = xmlSecBase64Decode(str, baseBuffer->data, baseBuffer->maxSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Decode - %d", ret);
	return(-1);
    }
    baseBuffer->size = ret;
    return(0);
}

static void
xmlSecBufferKlassInit(xmlSecObjKlassPtr klass) {
    xmlSecSObjKlassPtr sobjKlass = (xmlSecSObjKlassPtr)klass;
    xmlSecBaseBufferKlassPtr baseBufferKlass = (xmlSecBaseBufferKlassPtr)klass;
    
    xmlSecAssert(sobjKlass != NULL);
    xmlSecAssert(baseBufferKlass != NULL);

    klass->debugDump 		= xmlSecBufferDebugDump;
    klass->debugXmlDump 	= xmlSecBufferDebugXmlDump;
    sobjKlass->readXml		= xmlSecBufferReadXml; 
    sobjKlass->writeXml		= xmlSecBufferWriteXml; 
    sobjKlass->readBinary	= xmlSecBufferReadBinary; 
    sobjKlass->writeBinary	= xmlSecBufferWriteBinary; 
    baseBufferKlass->itemSize	= sizeof(unsigned char);
}

static void
xmlSecBufferDebugDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecBaseBufferPtr baseBuffer = xmlSecBaseBufferCast(obj);
    xmlSecBufferPtr buf = xmlSecBufferCast(obj);
    xmlChar*  str;
    
    xmlSecAssert(baseBuffer != NULL);
    xmlSecAssert(buf != NULL);
    xmlSecAssert(output != NULL);

    str = xmlSecBufferBase64Encode(buf, 2 * baseBuffer->size); /* make it one line */
    if(str == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecBufferBase64Encode");
	return;
    }
    
    xmlSecObjDebugIndent(output, level);
    fprintf(output, "buffer size: %d\n", baseBuffer->size);
    xmlSecObjDebugIndent(output, level);
    fprintf(output, "buffer data: %s\n", str);

    xmlFree(str); 
}

static void
xmlSecBufferDebugXmlDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecBaseBufferPtr baseBuffer = xmlSecBaseBufferCast(obj);
    xmlSecBufferPtr buf = xmlSecBufferCast(obj);
    xmlChar* str;
	    
    xmlSecAssert(baseBuffer != NULL);
    xmlSecAssert(buf != NULL);
    xmlSecAssert(output != NULL);

    str = xmlSecBufferBase64Encode(buf, 0);
    if(str == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecBufferBase64Encode");
	return;
    }
    
    xmlSecObjDebugIndent(output, level);
    fprintf(output, "<Buffer size=\"%d\">\n", baseBuffer->size);
    fprintf(output, "%s\n", str);
    xmlSecObjDebugIndent(output, level);
    fprintf(output, "</Buffer>\n");

    xmlFree(str); 
}

static int
xmlSecBufferReadXml(xmlSecSObjPtr sobj, xmlSecObjPtr ctx ATTRIBUTE_UNUSED, xmlNodePtr node) {
    xmlSecBufferPtr buf = xmlSecBufferCast(sobj);
    xmlChar* nodeContent;
    int ret;
    
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    
    nodeContent = xmlNodeGetContent(node);
    if(nodeContent == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XML_FAILED,	
		    "xmlNodeGetContent");
	return(-1);
    }
    
    ret = xmlSecBufferBase64Decode(buf, nodeContent);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecBufferBase64Decode - %d", ret);
	xmlFree(nodeContent);
	return(-1);
    }
    xmlFree(nodeContent);
    return(0);
}

static int
xmlSecBufferWriteXml(xmlSecSObjPtr sobj, xmlSecObjPtr ctx ATTRIBUTE_UNUSED, xmlNodePtr node) {
    xmlSecBufferPtr buf = xmlSecBufferCast(sobj);
    xmlChar* nodeContent;
    
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    
    nodeContent = xmlSecBufferBase64Encode(buf, 0);
    if(nodeContent == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecBufferBase64Encode");
	return(-1);
    }
    xmlNodeSetContent(node, nodeContent);
    xmlFree(nodeContent);
    return(0);    
}

static int
xmlSecBufferReadBinary(xmlSecSObjPtr sobj, xmlSecObjPtr ctx ATTRIBUTE_UNUSED, const unsigned char *data, size_t size) {
    xmlSecBufferPtr buf = xmlSecBufferCast(sobj);
    
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    
    return(xmlSecBufferSet(buf, data, size));
}

static int
xmlSecBufferWriteBinary(xmlSecSObjPtr sobj, xmlSecObjPtr ctx ATTRIBUTE_UNUSED, xmlSecBufferPtr buf) {
    xmlSecBaseBufferPtr baseBufferSrc = xmlSecBaseBufferCast(sobj);
    xmlSecBufferPtr bufSrc = xmlSecBufferCast(sobj);
    
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(baseBufferSrc != NULL, -1);
    xmlSecAssert2(bufSrc != NULL, -1);
    
    return(xmlSecBufferSet(buf, 
		xmlSecBufferGetBuffer(bufSrc),  
		xmlSecBaseBufferGetSize(baseBufferSrc)));    
}


