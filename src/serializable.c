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

static void		xmlSecBufferKlassInit		(xmlSecObjKlassPtr klass);
static int		xmlSecBufferConstructor		(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr obj);
static int		xmlSecBufferDuplicator		(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr dst, 
							 xmlSecObjPtr src);
static void		xmlSecBufferDestructor		(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr dst);
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
    xmlSecSObjKlassPtr sobjKlass = xmlSecSObjKlassCast(xmlSecObjGetKlass(sobj));

    xmlSecAssert2(sobj != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(sobjKlass != NULL, -1);

    if(sobjKlass->readXml == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_OBJECT_FAILED,	
		    "readXml(\"%s\")", 
    		    xmlSecObjKlassGetKlassName(xmlSecObjKlassCast(sobjKlass)));
	return(-1);
    }
    return((sobjKlass->readXml)(sobj, ctx, node));
}

int
xmlSecSObjReadBinary(xmlSecSObjPtr sobj, xmlSecObjPtr ctx, 
		const unsigned char *buf, size_t size) {
    xmlSecSObjKlassPtr sobjKlass = xmlSecSObjKlassCast(xmlSecObjGetKlass(sobj));

    xmlSecAssert2(sobj != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(sobjKlass != NULL, -1);

    if(sobjKlass->readBinary == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_OBJECT_FAILED,	
		    "readBinary(\"%s\")", 
    		    xmlSecObjKlassGetKlassName(xmlSecObjKlassCast(sobjKlass)));
	return(-1);
    }
    return((sobjKlass->readBinary)(sobj, ctx, buf, size));
}

int
xmlSecSObjWriteXml(xmlSecSObjPtr sobj, xmlSecObjPtr ctx, xmlNodePtr node) {
    xmlSecSObjKlassPtr sobjKlass = xmlSecSObjKlassCast(xmlSecObjGetKlass(sobj));

    xmlSecAssert2(sobj != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(sobjKlass != NULL, -1);

    if(sobjKlass->writeXml == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_OBJECT_FAILED,	
		    "writeXml(\"%s\")", 
    		    xmlSecObjKlassGetKlassName(xmlSecObjKlassCast(sobjKlass)));
	return(-1);
    }
    return((sobjKlass->writeXml)(sobj, ctx, node));
}

int
xmlSecSObjWriteBinary(xmlSecSObjPtr sobj, xmlSecObjPtr ctx, xmlSecBufferPtr buf) {
    xmlSecSObjKlassPtr sobjKlass = xmlSecSObjKlassCast(xmlSecObjGetKlass(sobj));

    xmlSecAssert2(sobj != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(sobjKlass != NULL, -1);

    if(sobjKlass->writeBinary == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_OBJECT_FAILED,	
		    "writeBinary(\"%s\")", 
    		    xmlSecObjKlassGetKlassName(xmlSecObjKlassCast(sobjKlass)));
	return(-1);
    }
    return((sobjKlass->writeBinary)(sobj, ctx, buf));
}


/*********************************************************************
 *
 * Binary Buffer
 *
 *********************************************************************/
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
	    xmlSecBufferConstructor,	/* xmlSecObjKlassConstructorMethod */
	    xmlSecBufferDuplicator,	/* xmlSecObjKlassDuplicatorMethod */
	    xmlSecBufferDestructor,	/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
				       &kklassInfo, xmlSecSObjKlassId); 
    } 
    return(klass);   
}

unsigned char*
xmlSecBufferGetData(xmlSecBufferPtr buf) {
    xmlSecAssert2(buf != NULL, NULL);
    
    return(buf->data);
}

size_t
xmlSecBufferGetSize(xmlSecBufferPtr buf) {
    xmlSecAssert2(buf != NULL, 0);
    
    return(buf->size);
}

size_t
xmlSecBufferGetMaxSize(xmlSecBufferPtr buf) {
    xmlSecAssert2(buf != NULL, 0);
    
    return(buf->maxSize);
}

int
xmlSecBufferSet(xmlSecBufferPtr buf, const unsigned char* data, size_t size) {
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    
    ret = xmlSecBufferAllocate(buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecBufferAllocate(size=%d)", size);
	return(-1);
			
    }
    xmlSecAssert2(buf->data != NULL, -1);
    xmlSecAssert2(buf->maxSize >= size, -1);
    
    memcpy(buf->data, data, size);
    buf->size = size;
    return(0);
}

int
xmlSecBufferAppend(xmlSecBufferPtr buf, const unsigned char* data, size_t size) {
    xmlSecAssert2(buf != NULL, -1);
    
    return (xmlSecBufferInsert(buf, buf->size, data, size));
}

int
xmlSecBufferPrepend(xmlSecBufferPtr buf, const unsigned char* data, size_t size) {
    xmlSecAssert2(buf != NULL, -1);
    
    return (xmlSecBufferInsert(buf, 0, data, size));
}

int
xmlSecBufferInsert(xmlSecBufferPtr buf, size_t pos, const unsigned char* data, size_t size) {
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    
    ret = xmlSecBufferAllocate(buf, buf->size + size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecBufferAllocate(size=%d)", buf->size + size);
	return(-1);			
    }
    xmlSecAssert2(buf->data != NULL, -1);
    xmlSecAssert2(buf->maxSize >= buf->size + size, -1);
    
    if(pos < buf->size) {
	memmove(buf->data + pos + size, buf->data + pos, buf->size - pos);
    }
    memcpy(buf->data + pos, data, size);
    buf->size += size;
    return(0);    
}

void
xmlSecBufferRemove(xmlSecBufferPtr buf, size_t pos, size_t size) {
    xmlSecAssert(buf != NULL);
    
    if(pos + size < buf->size) {
        xmlSecAssert(buf->data != NULL);

	memmove(buf->data + pos, buf->data + pos + size, buf->size - pos - size);
	buf->size -= size;
    } else {
	buf->size = pos;
    }
}

void
xmlSecBufferEmpty(xmlSecBufferPtr buf) {
    xmlSecAssert(buf != NULL);

    if(buf->maxSize > 0) {
	xmlSecAssert(buf->data != NULL);
	memset(buf->data, 0, buf->maxSize);
    }
    buf->size = 0;
}

int
xmlSecBufferAllocate(xmlSecBufferPtr buf, size_t size) {
    unsigned char* p;
    
    xmlSecAssert2(buf != NULL, -1);
    
    if(size <= buf->maxSize) {
	return(0);
    }
    
    p = xmlRealloc(buf->data, size);
    if(p == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", size);
	return(-1);
    }
    
    buf->data = p;
    buf->maxSize = size;
    return(0);
}

/* base 64 */
xmlChar*
xmlSecBufferBase64Encode(xmlSecBufferPtr buf, int columns) {
    xmlSecAssert2(buf != NULL, NULL);

    if(buf->size > 0) {
	xmlSecAssert2(buf->data != NULL, NULL);
	
	return(xmlSecBase64Encode(buf->data, buf->size, columns));
    }
    return(xmlStrdup(BAD_CAST ""));
}

int
xmlSecBufferBase64Decode(xmlSecBufferPtr buf, const xmlChar* str) {
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(str != NULL, -1);

    ret = xmlSecBufferAllocate(buf, xmlStrlen(str));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferAllocate - %d", ret);
	return(-1);
    }
    
    ret = xmlSecBase64Decode(str, buf->data, buf->maxSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Decode - %d", ret);
	return(-1);
    }
    return(0);
}

static void
xmlSecBufferKlassInit(xmlSecObjKlassPtr klass) {
    xmlSecSObjKlassPtr sobjKlass = xmlSecSObjKlassCast(klass);
    
    xmlSecAssert(sobjKlass != NULL);

    klass->debugDump 		= xmlSecBufferDebugDump;
    klass->debugXmlDump 	= xmlSecBufferDebugXmlDump;
    sobjKlass->readXml		= xmlSecBufferReadXml; 
    sobjKlass->writeXml		= xmlSecBufferWriteXml; 
    sobjKlass->readBinary	= xmlSecBufferReadBinary; 
    sobjKlass->writeBinary	= xmlSecBufferWriteBinary; 
}

static int
xmlSecBufferConstructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr obj) {
    xmlSecBufferPtr buf = xmlSecBufferCast(obj);

    xmlSecAssert2(buf != NULL, -1);

    buf->data 	= NULL;
    buf->size	= 0;
    buf->maxSize= 0;
    
    return(0);
}

static int
xmlSecBufferDuplicator(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr dst, xmlSecObjPtr src) {
    xmlSecBufferPtr bufDst = xmlSecBufferCast(dst);
    xmlSecBufferPtr bufSrc = xmlSecBufferCast(src);
    
    xmlSecAssert2(bufDst != NULL, -1);
    xmlSecAssert2(bufSrc != NULL, -1);
    
    return(xmlSecBufferSet(bufDst, 
		xmlSecBufferGetData(bufSrc),  
		xmlSecBufferGetSize(bufSrc)));		
}

static void
xmlSecBufferDestructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
				    xmlSecObjPtr obj) {
    xmlSecBufferPtr buf = xmlSecBufferCast(obj);

    xmlSecAssert(buf != NULL);

    xmlSecBufferEmpty(buf);
    if(buf->data != NULL) {
	xmlFree(buf->data);
    }
    buf->data 	= NULL;
    buf->size	= 0;
    buf->maxSize= 0;
}

static void
xmlSecBufferDebugDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecBufferPtr buf = xmlSecBufferCast(obj);
    xmlChar*  str;
    
    xmlSecAssert(buf != NULL);
    xmlSecAssert(output != NULL);

    str = xmlSecBufferBase64Encode(buf, buf->size); /* make it one line */
    if(str == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecBufferBase64Encode");
	return;
    }
    
    xmlSecObjDebugIndent(output, level);
    fprintf(output, "buffer size: %d\n", buf->size);
    xmlSecObjDebugIndent(output, level);
    fprintf(output, "buffer data: %s\n", str);

    xmlFree(str); 
}

static void
xmlSecBufferDebugXmlDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecBufferPtr buf = xmlSecBufferCast(obj);
    xmlChar* str;
	    
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
    fprintf(output, "<Buffer size=\"%d\">\n", buf->size);
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
    xmlSecBufferPtr bufSrc = xmlSecBufferCast(sobj);
    
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSrc != NULL, -1);
    
    return(xmlSecBufferSet(buf, 
		xmlSecBufferGetData(bufSrc),  
		xmlSecBufferGetSize(bufSrc)));    
}
