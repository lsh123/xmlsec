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



static int		xmlSecInputUriTransformInitialize	(xmlSecTransformPtr transform);
static void		xmlSecInputUriTransformFinalize		(xmlSecTransformPtr transform);
static int		xmlSecInputUriTransformPopBin		(xmlSecTransformPtr transform, 
								 unsigned char* data,
								 size_t* dataSize,
								 xmlSecTransformCtxPtr transformCtx);

static const struct _xmlSecTransformKlass xmlSecInputUriTransformId = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    sizeof(xmlSecTransform),		/* size_t objSize */


    /* same as xmlSecTransformId */    
    BAD_CAST "input-uri",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    0,					/* xmlSecAlgorithmUsage usage; */
    NULL,				/* const xmlChar href; */

    xmlSecInputUriTransformInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecInputUriTransformFinalize,	/* xmlSecTransformFinalizeMethod finalize; */
    NULL,				/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecInputUriTransformPopBin,	/* xmlSecTransformPopBinMethod popBin; */
    NULL,				/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,				/* xmlSecTransformPopXmlMethod popXml; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};
xmlSecTransformId xmlSecInputUri = (xmlSecTransformId)&xmlSecInputUriTransformId;

#define xmlSecInputUriTransformReadClbk( t ) \
    ( ( (xmlSecTransformCheckId(t, xmlSecInputUri)) && \
	( (t)->reserved1 != NULL ) ) ? \
	((xmlSecInputCallbackPtr)(t)->reserved1)->readcallback : \
	NULL )
#define xmlSecInputUriTransformCloseClbk( t ) \
    ( ( (xmlSecTransformCheckId(t, xmlSecInputUri)) && \
	( (t)->reserved1 != NULL ) ) ? \
	((xmlSecInputCallbackPtr)(t)->reserved1)->closecallback : \
	NULL )

/** 
 * xmlSecInputUriTransformInitialize:
 */
static int
xmlSecInputUriTransformInitialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecInputUri), -1);

    transform->reserved0 = transform->reserved1 = NULL;
    return(0);
}

/** 
 * xmlSecInputUriTransformFinalilze:
 */
static void
xmlSecInputUriTransformFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecInputUri));

    if((transform->reserved0 != NULL) && (xmlSecInputUriTransformCloseClbk(transform) != NULL)) {
	xmlSecInputUriTransformCloseClbk(transform)(transform->reserved0);
    }
    transform->reserved0 = transform->reserved1 = NULL;
}

/** 
 * xmlSecInputUriTransformOpen:
 * @transform: the pointer to IO transform.
 * @uri: the URL to open.
 *
 * Opens the given @uri for reading.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecInputUriTransformOpen(xmlSecTransformPtr transform, const char *uri) {
    xmlSecTransformPtr t;
    int i;
    char *unescaped;
        
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecInputUri), -1);
    xmlSecAssert2(uri != NULL, -1);

    t = (xmlSecTransformPtr)transform;
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
		t->reserved0 = xmlSecInputCallbackTable[i].opencallback(unescaped);
		if (t->reserved0 != NULL) {
		    t->reserved1 = &(xmlSecInputCallbackTable[i]);
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
    if (t->reserved0 == NULL) {
	for (i = xmlSecInputCallbackNr - 1;i >= 0;i--) {
	    if ((xmlSecInputCallbackTable[i].matchcallback != NULL) &&
		(xmlSecInputCallbackTable[i].matchcallback(uri) != 0)) {
		t->reserved0 = xmlSecInputCallbackTable[i].opencallback(uri);
		if (t->reserved0 != NULL) {
		    t->reserved1 = &(xmlSecInputCallbackTable[i]);
		    break;
		}
	    }
	}
    }

    if(t->reserved0 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "uri=%s (errno=%d)", uri, errno);
	return(-1);
    }
    
    return(0);
}

static int 
xmlSecInputUriTransformPopBin(xmlSecTransformPtr transform, unsigned char* data,
			    size_t* dataSize, xmlSecTransformCtxPtr transformCtx) {
    int ret;
    			    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecInputUri), -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    
    if(xmlSecInputUriTransformReadClbk(transform) != NULL) {
	ret = (xmlSecInputUriTransformReadClbk(transform))(transform->reserved0, 
					    	(char*)data, (int)(*dataSize));
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecInputUriTransformReadClbk",
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
    xmlSecRegisterDefaultInputCallbacks();
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
    xmlSecCleanupInputCallbacks();
}

/**
 * xmlSecCleanupInputCallbacks:
 *
 * Clears the entire input callback table. this includes the
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
xmlSecRegisterInputCallbacks(xmlInputMatchCallback matchFunc,
	xmlInputOpenCallback openFunc, xmlInputReadCallback readFunc,
	xmlInputCloseCallback closeFunc) {

    if (xmlSecInputCallbackNr >= MAX_INPUT_CALLBACK) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "too many input callbacks (>%d)", MAX_INPUT_CALLBACK);
	return(-1);
    }
    xmlSecInputCallbackTable[xmlSecInputCallbackNr].matchcallback = matchFunc;
    xmlSecInputCallbackTable[xmlSecInputCallbackNr].opencallback = openFunc;
    xmlSecInputCallbackTable[xmlSecInputCallbackNr].readcallback = readFunc;
    xmlSecInputCallbackTable[xmlSecInputCallbackNr].closecallback = closeFunc;
    return(xmlSecInputCallbackNr++);
}



