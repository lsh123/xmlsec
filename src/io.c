/** 
 * XMLSec library
 *
 * Input Uri transform
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h> 

#include <libxml/tree.h>

#ifdef LIBXML_HTTP_ENABLED
#include <libxml/nanohttp.h>
#endif /* LIBXML_HTTP_ENABLED */

#ifdef LIBXML_FTP_ENABLED 
#include <libxml/nanoftp.h>
#endif /* LIBXML_FTP_ENABLED */

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/keys.h>
#include <xmlsec/io.h>


static xmlSecTransformPtr xmlSecInputUriTransformCreate	(xmlSecTransformId id);
static void		xmlSecInputUriTransformDestroy	(xmlSecTransformPtr transform);
static int  		xmlSecInputUriTransformRead	(xmlSecBinTransformPtr transform, 
							 unsigned char *buf, 
							 size_t size);
static int		xmlSecFileRead			(FILE *f,
							 unsigned char *buf,
							 size_t size);

static const struct _xmlSecBinTransformId xmlSecInputUriTransformId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    0,					/* xmlSecAlgorithmUsage usage; */
    NULL,				/* const xmlChar href; */

    xmlSecInputUriTransformCreate, 	/* xmlSecTransformCreateMethod create; */
    xmlSecInputUriTransformDestroy,	/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary methods */
    xmlSecKeyIdUnknown,
    xmlSecKeyTypeAny,			/* xmlSecKeyType encryption; */
    xmlSecKeyTypeAny,			/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeNone,	/* xmlSecBinTransformSubType binSubType; */
    NULL,				/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecInputUriTransformRead,	/* xmlSecBinTransformReadMethod readBin; */
    NULL,				/* xmlSecBinTransformWriteMethod writeBin; */
    NULL, 				/* xmlSecBinTransformFlushMethod flushBin; */
};
xmlSecTransformId xmlSecInputUri = (xmlSecTransformId)&xmlSecInputUriTransformId;

typedef struct _xmlSecInputUriTransform {	
    /* same as for xmlSecTransform */
    xmlSecBinTransformId 		id;    
    xmlSecTransformStatus		status;
    int					dontDestroy;
    void				*data;
    
    /* xmlSecBinTransform specific */
    int					encode;
    int					finished;
    xmlSecBinTransformPtr		next;
    xmlSecBinTransformPtr		prev;   
    void				*binData;
    
    /* xmlSecInputUriTransform specific */    
    xmlSecInputUriTransformReadCallback	readInputUri;
    xmlSecInputUriTransformCloseCallback closeInputUri;    
} xmlSecInputUriTransform, *xmlSecInputUriTransformPtr;


/** 
 * xmlSecInputUriTransformOpen:
 *
 */
int
xmlSecInputUriTransformOpen(xmlSecTransformPtr transform, const char *uri) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecInputUriTransformOpen";
    xmlSecInputUriTransformPtr t;
        
    if(!xmlSecTransformCheckId(transform, xmlSecInputUri) || (uri == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or uri == NULL\n",
	    func);	
#endif 	    
	return(-1);
    }

    t = (xmlSecInputUriTransformPtr)transform;
    /* todo: add an ability to use custom protocol handlers */
#ifdef LIBXML_HTTP_ENABLED    
    if(strncmp(uri, "http://", 7) == 0) {
	t->data = xmlNanoHTTPOpen(uri, NULL);
	t->readInputUri = (xmlSecInputUriTransformReadCallback)xmlNanoHTTPRead;
	t->closeInputUri = (xmlSecInputUriTransformCloseCallback)xmlNanoHTTPClose;
    } else 
#endif /* LIBXML_HTTP_ENABLED */     

#ifdef LIBXML_FTP_ENABLED        
    if(strncmp(uri, "ftp://", 6) == 0) { 
	t->data = xmlNanoFTPOpen(uri);
	t->readInputUri = (xmlSecInputUriTransformReadCallback)xmlNanoFTPRead;
	t->closeInputUri = (xmlSecInputUriTransformCloseCallback)xmlNanoFTPClose;
    } else
#endif /* LIBXML_FTP_ENABLED */     

    {
	FILE *fd;
	const char *path = NULL;
	
	/* try to open local file */
	if(strncmp(uri, "file://localhost", 16) == 0) {
	    path = &uri[16];
	} else if(strncmp(uri, "file:///", 8) == 0) {
#if defined (_WIN32) && !defined(__CYGWIN__)
	    path = &uri[8];
#else
	    path = &uri[7];
#endif
	} else {
	    path = uri;
	}
#if defined(WIN32) || defined (__CYGWIN__)
	fd = fopen(path, "rb");
#else
	fd = fopen(path, "r");
#endif /* WIN32 */
	t->data = fd;
	t->readInputUri = (xmlSecInputUriTransformReadCallback)xmlSecFileRead;
	t->closeInputUri = (xmlSecInputUriTransformCloseCallback)fclose;
    }

    if(t->data == NULL) {
        xmlGenericError(xmlGenericErrorContext,
	    "%s: unable to open file \"%s\"\n", 
	    func, uri);
	return(-1);
    }
    
    return(0);
}

/** 
 * xmlSecInputUriTransformCreate:
 * @id: 
 *
 * Creates new trasnform object.
 */
static xmlSecTransformPtr 
xmlSecInputUriTransformCreate(xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecInputUriTransformCreate";
    xmlSecInputUriTransformPtr ptr;

    if((id == NULL) || (id != xmlSecInputUri)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: id is null or id %d is not recognized\n",
	    func, id);
#endif 	    
	return(NULL);
    }
    
    /*
     * Allocate a new xmlSecInputUriTransform and fill the fields.
     */
    ptr = (xmlSecInputUriTransformPtr) xmlMalloc(sizeof(xmlSecInputUriTransform));
    if(ptr == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xmlSecInputUriTransform malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(ptr, 0, sizeof(xmlSecInputUriTransform));
    
    ptr->id = (xmlSecBinTransformId)id;
    return((xmlSecTransformPtr)ptr);
}

/** 
 * xmlSecInputUriTransformDestroy:
 * @transform
 *
 * Destroys the object
 */
static void
xmlSecInputUriTransformDestroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecInputUriTransformDestroy";
    xmlSecInputUriTransformPtr t;
    
    if(!xmlSecTransformCheckId(transform, xmlSecInputUri)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return;
    }
    
    t = (xmlSecInputUriTransformPtr)transform;
    if(t->closeInputUri) {
	t->closeInputUri(t->data);
    }
    memset(t, 0, sizeof(xmlSecInputUriTransform));
    xmlFree(t);
}

/** 
 * xmlSecInputUriTransformRead:
 * @transform:
 * @buf:
 * @size:
 *
 * Reads data from buffer
 */
static int
xmlSecInputUriTransformRead(xmlSecBinTransformPtr transform, 
			 unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecInputUriTransformRead";
    xmlSecInputUriTransformPtr t;
    
    if(!xmlSecTransformCheckId(transform, xmlSecInputUri)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    t = (xmlSecInputUriTransformPtr)transform;
    if(t->readInputUri) {
	int ret;

	ret = t->readInputUri(t->data, buf, size);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
		"%s: transform read failed\n",
	        func);	
#endif 	    
	    return(-1);
	}
	return(ret);
    }
    return(0);
}

/** 
 * xmlSecFileRead:
 * @f:
 * @buf:
 * @size:
 *
 * Reads data from local file
 */
static int
xmlSecFileRead(FILE *f,  unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecFileRead";

    if(f == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: file descriptor is null\n",
	    func);	
#endif 	    
	return(-1);
    }
    return (fread(buf, sizeof(unsigned char), size, f));
}


void
xmlSecIOInit(void) {
#ifdef LIBXML_HTTP_ENABLED
    xmlNanoHTTPInit();
#endif /* LIBXML_HTTP_ENABLED */
#ifdef LIBXML_FTP_ENABLED       
    xmlNanoFTPInit();
#endif /* LIBXML_FTP_ENABLED */ 
}

void
xmlSecIOShutdown(void) {
#ifdef LIBXML_HTTP_ENABLED
    xmlNanoHTTPCleanup();
#endif /* LIBXML_HTTP_ENABLED */
#ifdef LIBXML_FTP_ENABLED       
    xmlNanoFTPCleanup();
#endif /* LIBXML_FTP_ENABLED */ 
}








