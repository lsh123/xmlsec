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
#include <errno.h>

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
#include <xmlsec/errors.h>

/*
 * Input I/O callback sets
 */
typedef struct _xmlSecIOCallback {
    xmlInputMatchCallback matchcallback;
    xmlInputOpenCallback opencallback;
    xmlInputReadCallback readcallback;
    xmlInputCloseCallback closecallback;
} xmlSecIOCallback, *xmlSecIOCallbackPtr;

#define MAX_INPUT_CALLBACK 15

static xmlSecIOCallback xmlSecIOCallbackTable[MAX_INPUT_CALLBACK];
static int xmlSecIOCallbackNr = 0;
static int xmlSecIOCallbackInitialized = 0;

/**
 * xmlSecIOInit:
 *
 * The IO initialization (called from xmlSecInit() function).
 * Applications should not call this function directly.
 */ 
void
xmlSecIOInit(void) {    

#ifdef LIBXML_HTTP_ENABLED
    xmlNanoHTTPInit();
#endif /* LIBXML_HTTP_ENABLED */

#ifdef LIBXML_FTP_ENABLED       
    xmlNanoFTPInit();
#endif /* LIBXML_FTP_ENABLED */ 

    xmlSecIORegisterDefaultCallbacks();
}

/**
 * xmlSecIOShutdown:
 *
 * The IO clenaup (called from xmlSecShutdown() function).
 * Applications should not call this function directly.
 */ 
void
xmlSecIOShutdown(void) {

#ifdef LIBXML_HTTP_ENABLED
    xmlNanoHTTPCleanup();
#endif /* LIBXML_HTTP_ENABLED */

#ifdef LIBXML_FTP_ENABLED       
    xmlNanoFTPCleanup();
#endif /* LIBXML_FTP_ENABLED */ 

    xmlSecIOCleanupCallbacks();
}

/**
 * xmlSecIOCleanupCallbacks:
 *
 * Clears the entire input callback table. this includes the
 * compiled-in I/O. 
 */
void
xmlSecIOCleanupCallbacks(void)
{
    int i;

    if (!xmlSecIOCallbackInitialized)
        return;

    for (i = xmlSecIOCallbackNr - 1; i >= 0; i--) {
        xmlSecIOCallbackTable[i].matchcallback = NULL;
        xmlSecIOCallbackTable[i].opencallback = NULL;
        xmlSecIOCallbackTable[i].readcallback = NULL;
        xmlSecIOCallbackTable[i].closecallback = NULL;
    }

    xmlSecIOCallbackNr = 0;
}

/**
 * xmlSecIORegisterDefaultCallbacks:
 *
 * Registers the default compiled-in I/O handlers.
 */
void
xmlSecIORegisterDefaultCallbacks(void) {
    if (xmlSecIOCallbackInitialized) {
	return;
    }
    
    xmlSecIORegisterCallbacks(xmlFileMatch, xmlFileOpen,
	                      xmlFileRead, xmlFileClose);
#ifdef LIBXML_HTTP_ENABLED
    xmlSecIORegisterCallbacks(xmlIOHTTPMatch, xmlIOHTTPOpen,
	                      xmlIOHTTPRead, xmlIOHTTPClose);
#endif /* LIBXML_HTTP_ENABLED */

#ifdef LIBXML_FTP_ENABLED
    xmlSecIORegisterCallbacks(xmlIOFTPMatch, xmlIOFTPOpen,
	                      xmlIOFTPRead, xmlIOFTPClose);
#endif /* LIBXML_FTP_ENABLED */

    xmlSecIOCallbackInitialized = 1;
}

/**
 * xmlSecIORegisterCallbacks:
 * @matchFunc:  the xmlInputMatchCallback.
 * @openFunc:  the xmlInputOpenCallback.
 * @readFunc:  the xmlInputReadCallback.
 * @closeFunc:  the xmlInputCloseCallback.
 *
 * Register a new set of I/O callback for handling parser input.
 *
 * Returns the registered handler number or a negative value if 
 * an error occurs.
 */
int
xmlSecIORegisterCallbacks(xmlInputMatchCallback matchFunc,
	xmlInputOpenCallback openFunc, xmlInputReadCallback readFunc,
	xmlInputCloseCallback closeFunc) {

    if (xmlSecIOCallbackNr >= MAX_INPUT_CALLBACK) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "too many input callbacks (>%d)", MAX_INPUT_CALLBACK);
	return(-1);
    }
    xmlSecIOCallbackTable[xmlSecIOCallbackNr].matchcallback = matchFunc;
    xmlSecIOCallbackTable[xmlSecIOCallbackNr].opencallback = openFunc;
    xmlSecIOCallbackTable[xmlSecIOCallbackNr].readcallback = readFunc;
    xmlSecIOCallbackTable[xmlSecIOCallbackNr].closecallback = closeFunc;
    return(xmlSecIOCallbackNr++);
}



/**************************************************************
 *
 * Input URI Transform
 *
 * reserved0 --> callbacks list (xmlSecIOCallbackPtr)
 * reserved1 --> callback specific ctx
 * 
 **************************************************************/
#define xmlSecTransformInputURIGetCallbacks(transform) \
    ((xmlSecTransformCheckId(transform, xmlSecTransformInputURIId)) ?  \
     ((xmlSecIOCallbackPtr)(transform)->reserved0) : NULL)
#define xmlSecTransformInputURIGetCtx(transform) \
    ((xmlSecTransformCheckId(transform, xmlSecTransformInputURIId)) ?  \
     ((xmlSecIOCallbackPtr)(transform)->reserved1) : NULL)
#define xmlSecTransformInputURIGetReadCallback(transform) \
    ((xmlSecTransformInputURIGetCallbacks(transform) != NULL) ? \
      xmlSecTransformInputURIGetCallbacks(transform)->readcallback : NULL)
#define xmlSecTransformInputURIGetCloseCallback( transform ) \
    ((xmlSecTransformInputURIGetCallbacks(transform) != NULL) ? \
      xmlSecTransformInputURIGetCallbacks(transform)->closecallback : NULL)

static int		xmlSecTransformInputURIInitialize	(xmlSecTransformPtr transform);
static void		xmlSecTransformInputURIFinalize		(xmlSecTransformPtr transform);
static int		xmlSecTransformInputURIPopBin		(xmlSecTransformPtr transform, 
								 unsigned char* data,
								 size_t maxDataSize,
								 size_t* dataSize,
								 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecTransformInputURIKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    sizeof(xmlSecTransform),		/* size_t objSize */

    BAD_CAST "input-uri",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    0,					/* xmlSecAlgorithmUsage usage; */
    NULL,				/* const xmlChar href; */

    xmlSecTransformInputURIInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformInputURIFinalize,	/* xmlSecTransformFinalizeMethod finalize; */
    NULL,				/* xmlSecTransformNodeReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,	/* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,				/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformInputURIPopBin,	/* xmlSecTransformPopBinMethod popBin; */
    NULL,				/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,				/* xmlSecTransformPopXmlMethod popXml; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};
xmlSecTransformId 
xmlSecTransformInputURIGetKlass(void) {
    return(&xmlSecTransformInputURIKlass);
}

/** 
 * xmlSecTransformInputURIOpen:
 * @transform: the pointer to IO transform.
 * @uri: the URL to open.
 *
 * Opens the given @uri for reading.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecTransformInputURIOpen(xmlSecTransformPtr transform, const xmlChar *uri) {
    int i;
    char *unescaped;
        
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformInputURIId), -1);
    xmlSecAssert2(uri != NULL, -1);

    /* todo: add an ability to use custom protocol handlers */

    /*
     * Try to find one of the input accept method accepting that scheme
     * Go in reverse to give precedence to user defined handlers.
     * try with an unescaped version of the uri
     */
    unescaped = xmlURIUnescapeString((char*)uri, 0, NULL);
    if (unescaped != NULL) {
	for (i = xmlSecIOCallbackNr - 1;i >= 0;i--) {
	    if ((xmlSecIOCallbackTable[i].matchcallback != NULL) &&
		(xmlSecIOCallbackTable[i].matchcallback(unescaped) != 0)) {
		transform->reserved1 = xmlSecIOCallbackTable[i].opencallback(unescaped);
		if (transform->reserved1 != NULL) {
		    transform->reserved0 = &(xmlSecIOCallbackTable[i]);
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
    if (transform->reserved1 == NULL) {
	for (i = xmlSecIOCallbackNr - 1;i >= 0;i--) {
	    if ((xmlSecIOCallbackTable[i].matchcallback != NULL) &&
		(xmlSecIOCallbackTable[i].matchcallback(uri) != 0)) {
		transform->reserved1 = xmlSecIOCallbackTable[i].opencallback(uri);
		if (transform->reserved1 != NULL) {
		    transform->reserved0 = &(xmlSecIOCallbackTable[i]);
		    break;
		}
	    }
	}
    }

    if(transform->reserved1 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "uri=%s (errno=%d)", uri, errno);
	return(-1);
    }
    
    return(0);
}



/** 
 * xmlSecTransformInputURIInitialize:
 */
static int
xmlSecTransformInputURIInitialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformInputURIId), -1);

    transform->reserved0 = transform->reserved1 = NULL;
    return(0);
}

/** 
 * xmlSecTransformInputURIFinalilze:
 */
static void
xmlSecTransformInputURIFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecTransformInputURIId));

    if((xmlSecTransformInputURIGetCtx(transform) != NULL) &&
       (xmlSecTransformInputURIGetCloseCallback(transform) != NULL)) {

	(xmlSecTransformInputURIGetCloseCallback(transform))(
		    xmlSecTransformInputURIGetCtx(transform));
    }
    transform->reserved0 = transform->reserved1 = NULL;
}

static int 
xmlSecTransformInputURIPopBin(xmlSecTransformPtr transform, unsigned char* data,
			      size_t maxDataSize, size_t* dataSize, 
			      xmlSecTransformCtxPtr transformCtx) {
    int ret;
    			    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformInputURIId), -1);
    xmlSecAssert2(xmlSecTransformInputURIGetCtx(transform) != NULL, -1);
    xmlSecAssert2(xmlSecTransformInputURIGetCallbacks(transform) != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    
    if(xmlSecTransformInputURIGetReadCallback(transform) != NULL) {
        ret = (xmlSecTransformInputURIGetReadCallback(transform))(
		    xmlSecTransformInputURIGetCtx(transform), 
		    (char*)data, (int)maxDataSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecTransformInputURIGetReadCallback",
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "errno=%d", errno);
	    return(-1);
	}
	(*dataSize) = ret;
    } else {
	(*dataSize) = 0;
    }
    return(0);
}




