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

#include <libxml/uri.h>
#include <libxml/tree.h>
#include <libxml/xmlIO.h>

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



/*
 * Input I/O callback sets
 */
typedef struct _xmlSecInputCallback {
    xmlInputMatchCallback matchcallback;
    xmlInputOpenCallback opencallback;
    xmlInputReadCallback readcallback;
    xmlInputCloseCallback closecallback;
} xmlSecInputCallback, *xmlSecInputCallbackPtr;

#define MAX_INPUT_CALLBACK 15

static xmlSecInputCallback xmlSecInputCallbackTable[MAX_INPUT_CALLBACK];
static int xmlSecInputCallbackNr = 0;
static int xmlSecInputCallbackInitialized = 0;



static xmlSecTransformPtr xmlSecInputUriTransformCreate	(xmlSecTransformId id);
static void		xmlSecInputUriTransformDestroy	(xmlSecTransformPtr transform);
static int  		xmlSecInputUriTransformRead	(xmlSecBinTransformPtr transform, 
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

#define xmlSecInputUriTransformReadClbk( t ) \
    ( ( (xmlSecTransformCheckId(t, xmlSecInputUri)) && \
	( (t)->binData != NULL ) ) ? \
	((xmlSecInputCallbackPtr)(t)->binData)->readcallback : \
	NULL )
#define xmlSecInputUriTransformCloseClbk( t ) \
    ( ( (xmlSecTransformCheckId(t, xmlSecInputUri)) && \
	( (t)->binData != NULL ) ) ? \
	((xmlSecInputCallbackPtr)(t)->binData)->closecallback : \
	NULL )

/** 
 * xmlSecInputUriTransformCreate:
 * @id: 
 *
 * Creates new trasnform object.
 */
static xmlSecTransformPtr 
xmlSecInputUriTransformCreate(xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecInputUriTransformCreate";
    xmlSecBinTransformPtr ptr;

    if((id == NULL) || (id != xmlSecInputUri)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: id is null or id %d is not recognized\n",
	    func, id);
#endif 	    
	return(NULL);
    }
    
    /*
     * Allocate a new xmlSecBinTransform and fill the fields.
     */
    ptr = (xmlSecBinTransformPtr) xmlMalloc(sizeof(xmlSecBinTransform));
    if(ptr == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xmlSecBinTransform malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(ptr, 0, sizeof(xmlSecBinTransform));
    
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
    xmlSecBinTransformPtr t;
    
    if(!xmlSecTransformCheckId(transform, xmlSecInputUri)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return;
    }
    
    t = (xmlSecBinTransformPtr)transform;
    if((t->data != NULL) && (xmlSecInputUriTransformCloseClbk(t) != NULL)) {
	xmlSecInputUriTransformCloseClbk(t)(t->data);
    }
    memset(t, 0, sizeof(xmlSecBinTransform));
    xmlFree(t);
}

/** 
 * xmlSecInputUriTransformOpen:
 *
 */
int
xmlSecInputUriTransformOpen(xmlSecTransformPtr transform, const char *uri) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecInputUriTransformOpen";
    xmlSecBinTransformPtr t;
    int i;
    char *unescaped;
        
    if(!xmlSecTransformCheckId(transform, xmlSecInputUri) || (uri == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or uri == NULL\n",
	    func);	
#endif 	    
	return(-1);
    }

    t = (xmlSecBinTransformPtr)transform;
    /* todo: add an ability to use custom protocol handlers */

    /*
     * Try to find one of the input accept method accepting that scheme
     * Go in reverse to give precedence to user defined handlers.
     * try with an unescaped version of the uri
     */
    unescaped = xmlURIUnescapeString(uri, 0, NULL);
    if (unescaped != NULL) {
	for (i = xmlSecInputCallbackNr - 1;i >= 0;i--) {
	    if ((xmlSecInputCallbackTable[i].matchcallback != NULL) &&
		(xmlSecInputCallbackTable[i].matchcallback(unescaped) != 0)) {
		t->data = xmlSecInputCallbackTable[i].opencallback(unescaped);
		if (t->data != NULL) {
		    t->binData = &(xmlSecInputCallbackTable[i]);
		    break;
		}
	    }
	}
	xmlFree(unescaped);
    }

    /*
     * If this failed try with a non-escaped uri this may be a strange
     * filename
     */
    if (t->data == NULL) {
	for (i = xmlSecInputCallbackNr - 1;i >= 0;i--) {
	    if ((xmlSecInputCallbackTable[i].matchcallback != NULL) &&
		(xmlSecInputCallbackTable[i].matchcallback(uri) != 0)) {
		t->data = xmlSecInputCallbackTable[i].opencallback(uri);
		if (t->data != NULL) {
		    t->binData = &(xmlSecInputCallbackTable[i]);
		    break;
		}
	    }
	}
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
    xmlSecBinTransformPtr t;
    int ret;
    
    if(!xmlSecTransformCheckId(transform, xmlSecInputUri)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    t = (xmlSecBinTransformPtr)transform;
    if((t->data != NULL) && (xmlSecInputUriTransformReadClbk(t) != NULL)) {
	ret = xmlSecInputUriTransformReadClbk(t)(t->data, (char*)buf, (int)size);
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

void
xmlSecIOInit(void) {    
#ifdef LIBXML_HTTP_ENABLED
    xmlNanoHTTPInit();
#endif /* LIBXML_HTTP_ENABLED */
#ifdef LIBXML_FTP_ENABLED       
    xmlNanoFTPInit();
#endif /* LIBXML_FTP_ENABLED */ 
    xmlSecRegisterDefaultInputCallbacks();
}

void
xmlSecIOShutdown(void) {
#ifdef LIBXML_HTTP_ENABLED
    xmlNanoHTTPCleanup();
#endif /* LIBXML_HTTP_ENABLED */
#ifdef LIBXML_FTP_ENABLED       
    xmlNanoFTPCleanup();
#endif /* LIBXML_FTP_ENABLED */ 
    xmlSecCleanupInputCallbacks();
}




/**
 * xmlSecCleanupInputCallbacks:
 *
 * clears the entire input callback table. this includes the
 * compiled-in I/O. 
 */
void
xmlSecCleanupInputCallbacks(void)
{
    int i;

    if (!xmlSecInputCallbackInitialized)
        return;

    for (i = xmlSecInputCallbackNr - 1; i >= 0; i--) {
        xmlSecInputCallbackTable[i].matchcallback = NULL;
        xmlSecInputCallbackTable[i].opencallback = NULL;
        xmlSecInputCallbackTable[i].readcallback = NULL;
        xmlSecInputCallbackTable[i].closecallback = NULL;
    }

    xmlSecInputCallbackNr = 0;
}

/**
 * xmlSecRegisterDefaultInputCallbacks:
 *
 * Registers the default compiled-in I/O handlers.
 */
void
xmlSecRegisterDefaultInputCallbacks(void) {
    if (xmlSecInputCallbackInitialized)
	return;

    xmlSecRegisterInputCallbacks(xmlFileMatch, xmlFileOpen,
	                      xmlFileRead, xmlFileClose);
#ifdef LIBXML_HTTP_ENABLED
    xmlSecRegisterInputCallbacks(xmlIOHTTPMatch, xmlIOHTTPOpen,
	                      xmlIOHTTPRead, xmlIOHTTPClose);
#endif /* LIBXML_HTTP_ENABLED */

#ifdef LIBXML_FTP_ENABLED
    xmlSecRegisterInputCallbacks(xmlIOFTPMatch, xmlIOFTPOpen,
	                      xmlIOFTPRead, xmlIOFTPClose);
#endif /* LIBXML_FTP_ENABLED */
    xmlSecInputCallbackInitialized = 1;
}

/**
 * xmlSecRegisterInputCallbacks:
 * @matchFunc:  the xmlInputMatchCallback
 * @openFunc:  the xmlInputOpenCallback
 * @readFunc:  the xmlInputReadCallback
 * @closeFunc:  the xmlInputCloseCallback
 *
 * Register a new set of I/O callback for handling parser input.
 *
 * Returns the registered handler number or -1 in case of error
 */
int
xmlSecRegisterInputCallbacks(xmlInputMatchCallback matchFunc,
	xmlInputOpenCallback openFunc, xmlInputReadCallback readFunc,
	xmlInputCloseCallback closeFunc) {
    if (xmlSecInputCallbackNr >= MAX_INPUT_CALLBACK) {
	return(-1);
    }
    xmlSecInputCallbackTable[xmlSecInputCallbackNr].matchcallback = matchFunc;
    xmlSecInputCallbackTable[xmlSecInputCallbackNr].opencallback = openFunc;
    xmlSecInputCallbackTable[xmlSecInputCallbackNr].readcallback = readFunc;
    xmlSecInputCallbackTable[xmlSecInputCallbackNr].closecallback = closeFunc;
    return(xmlSecInputCallbackNr++);
}



