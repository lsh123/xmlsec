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
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/base64.h>
#include <xmlsec/membuf.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/io.h>

#include <xmlsec/xmlenc.h>

const xmlChar xmlSecEncTypeElement[] = "http://www.w3.org/2001/04/xmlenc#Element";
const xmlChar xmlSecEncTypeContent[] = "http://www.w3.org/2001/04/xmlenc#Content";

typedef struct _xmlSecEncState {
    xmlSecEncCtxPtr		ctx;
    xmlSecBinTransformPtr 	first;
    xmlSecBinTransformPtr	last;
    xmlNodePtr			cipherDataNode;
    int				encrypt;
    xmlChar 			*type;
    
} xmlSecEncState, *xmlSecEncStatePtr;

/** 
 * XML Enc state
 */
static xmlSecEncStatePtr	xmlSecEncStateCreate		(xmlSecEncCtxPtr ctx, 
								 xmlNodePtr encNode,
								 int encrypt,
								 xmlSecEncResultPtr result);
static void			xmlSecEncStateDestroy		(xmlSecEncStatePtr state);
static int			xmlSecEncStateWriteResult	(xmlSecEncStatePtr state,
								 xmlNodePtr node,
								 xmlSecEncResultPtr result);
static int			xmlSecEncStateAddFirstTransform	(xmlSecEncStatePtr state,
								 xmlSecTransformPtr transform);
static int			xmlSecEncStateAddTransform	(xmlSecEncStatePtr state,
								 xmlSecTransformPtr transform);

#define xmlSecEncResultIsValid(result) \
	    ((( result ) != NULL) && ((result)->ctx != NULL))
#define xmlSecEncResultGetKeyCallback(result) \
	    ( ( xmlSecEncResultIsValid((result)) ) ? \
		((result)->ctx->keysMngr->getKey) : \
		NULL )


static int			xmlSecEncryptedDataNodeRead	(xmlNodePtr encNode,
								 xmlSecEncStatePtr state, 
								 xmlSecEncResultPtr result);
static int			xmlSecCipherDataNodeRead	(xmlNodePtr cipherDataNode,
								 xmlSecEncStatePtr state, 							 
								 xmlSecEncResultPtr result);
static int 			xmlSecCipherDataNodeWrite	(xmlNodePtr cipherDataNode,
								 const unsigned char *buf,
								 size_t size);
static int			xmlSecCipherValueNodeRead	(xmlNodePtr cipherValueNode,
								 xmlSecEncStatePtr state, 
								 xmlSecEncResultPtr result);
static int			xmlSecCipherReferenceNodeRead	(xmlNodePtr cipherReferenceNode, 
								 xmlSecEncStatePtr state, 
								 xmlSecEncResultPtr result);


/**
 * XML Encrypiton context methods
 */
/**
 * xmlSecEncCtxCreate:
 *
 *
 *
 */
xmlSecEncCtxPtr		
xmlSecEncCtxCreate(xmlSecKeysMngrPtr keysMngr) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncCtxCreate";
    xmlSecEncCtxPtr ctx;
    
    /*
     * Allocate a new xmlSecEncCtx and fill the fields.
     */
    ctx = (xmlSecEncCtxPtr) xmlMalloc(sizeof(xmlSecEncCtx));
    if(ctx == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xmlSecEncCtx malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(ctx, 0, sizeof(xmlSecEncCtx));
    
    ctx->keysMngr = keysMngr;
    return(ctx);
}

/**
 * xmlSecEncCtxDestroy
 *
 *
 *
 */
void
xmlSecEncCtxDestroy(xmlSecEncCtxPtr ctx) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncCtxDestroy";
    if(ctx == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: context is null\n", 
	    func);	
#endif
	return;	    
    }
    
    memset(ctx, 0, sizeof(xmlSecEncCtx));
    xmlFree(ctx);
}


/** 
 * Encryption Template
 */
/** 
 * xmlSecEncDataCreate:
 * @id: the Id attribute of EncryptedData node (optional)
 * @type: the Type attribute of EncryptedData node (optional)
 * @mimeType: the MimeType attribute of EncryptedData node (optional)
 * @encoding: the Encoding attribute of EncryptedData node (optional)
 *
 * Creates new encryption template. 
 *
 * Returns the new template or NULL if an error occurs
 */
xmlNodePtr		
xmlSecEncDataCreate(const xmlChar *id, const xmlChar *type,
		    const xmlChar *mimeType, const xmlChar *encoding) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncDataCreate";
    xmlNodePtr encNode;
    xmlNodePtr cipherData;
    
    encNode = xmlNewNode(NULL, BAD_CAST "EncryptedData");
    if(encNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create new node\n", 
	    func);	
#endif
	return(NULL);	        
    }
    
    if(xmlNewNs(encNode, xmlSecEncNs, NULL) == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add namespace\n", 
	    func);	
#endif
	return(NULL);	        	
    }
    
    if(id != NULL) {
	xmlSetProp(encNode, BAD_CAST "Id", id);
    }
    if(type != NULL) {
	xmlSetProp(encNode, BAD_CAST "Type", type);
    }
    if(mimeType != NULL) {
	xmlSetProp(encNode, BAD_CAST "MimeType", mimeType);
    }
    if(encoding != NULL) {
	xmlSetProp(encNode, BAD_CAST "Encoding", encoding);
    }
    
    cipherData = xmlSecAddChild(encNode,  BAD_CAST "CipherData", xmlSecEncNs);
    if(cipherData == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add CipherData\n", 
	    func);	
#endif
	return(NULL);	        	
    }
    
    return(encNode);
}

/** 
 * xmlSecEncDataDestroy
 *
 *
 *
 */
void
xmlSecEncDataDestroy(xmlNodePtr encNode) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncDataDestroy";
        
    if((encNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: template is null\n", 
	    func);	
#endif
	return;	        
    }

    xmlUnlinkNode(encNode);
    xmlFreeNode(encNode);
}

/** 
 * xmlSecEncDataAddEncMethod
 *
 *
 *
 */
xmlNodePtr
xmlSecEncDataAddEncMethod(xmlNodePtr encNode, xmlSecTransformId encMethodId) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncDataAddEncMethod";
    xmlNodePtr encMethod;
    xmlNodePtr tmp;
    int ret;
    
    if((encNode == NULL) || (encMethodId == xmlSecTransformUnknown)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: template is null or transform unknown\n", 
	    func);	
#endif
	return(NULL);	        
    }
    
    encMethod = xmlSecFindChild(encNode, BAD_CAST "EncryptionMethod", xmlSecEncNs);
    if(encMethod != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: the EncryptionMethod node is already there\n", 
	    func);	
#endif
	return(NULL);	
    }
    
    tmp = xmlSecGetNextElementNode(encNode->children);
    if(tmp == NULL) {
	encMethod = xmlSecAddChild(encNode,  BAD_CAST "EncryptionMethod", xmlSecEncNs);
    } else {
	encMethod = xmlSecAddPrevSibling(tmp,  BAD_CAST "EncryptionMethod", xmlSecEncNs);
    }    
    if(encMethod == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create EncryptionMethod node\n", 
	    func);	
#endif
	return(NULL);	
    }
    
    ret = xmlSecTransformNodeWrite(encMethod, encMethodId);
    if(ret < 0){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: enc method write failed\n", 
	    func);	
#endif
	xmlUnlinkNode(encMethod);
	xmlFreeNode(encMethod);
	return(NULL);	
    }
    return(encMethod);
}

/** 
 * xmlSecEncDataAddKeyInfo
 *
 *
 *
 */
xmlNodePtr
xmlSecEncDataAddKeyInfo(xmlNodePtr encNode) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncDataAddKeyInfo";
    xmlNodePtr keyInfo;
    xmlNodePtr prev;
    xmlNodePtr tmp;
        
    if((encNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: template is null\n", 
	    func);	
#endif
	return(NULL);	        
    }

    keyInfo = xmlSecFindChild(encNode, BAD_CAST "KeyInfo", xmlSecDSigNs);
    if(keyInfo != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: the KeyInfo node is already there\n", 
	    func);	
#endif
	return(NULL);	
    }
    
    prev = xmlSecFindChild(encNode, BAD_CAST "EncryptionMethod", xmlSecEncNs);
    tmp = xmlSecGetNextElementNode(encNode->children);
    if(prev != NULL) {
	keyInfo = xmlSecAddNextSibling(prev, BAD_CAST "KeyInfo", xmlSecDSigNs);
    } else if(tmp == NULL) {
	keyInfo = xmlSecAddChild(encNode, BAD_CAST "KeyInfo", xmlSecDSigNs);
    } else {
	keyInfo = xmlSecAddPrevSibling(tmp, BAD_CAST "KeyInfo", xmlSecDSigNs);
    }
    if(keyInfo == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create keyInfo node\n", 
	    func);	
#endif
	return(NULL);	
    }
    return(keyInfo);
}

/** 
 * xmlSecEncDataAddEncProperties
 *
 *
 *
 */
xmlNodePtr
xmlSecEncDataAddEncProperties(xmlNodePtr encNode, const xmlChar *id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncDataAddEncProperties";
    xmlNodePtr encProps;
        
    if((encNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: template is null\n", 
	    func);	
#endif
	return(NULL);	        
    }

    encProps = xmlSecFindChild(encNode, BAD_CAST "EncryptionProperties", xmlSecEncNs);
    if(encProps != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: the EncryptionProperties node is already there\n", 
	    func);	
#endif
	return(NULL);	
    }

    encProps = xmlSecAddChild(encNode, BAD_CAST "EncryptionProperties", xmlSecEncNs);
    if(encProps == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create EncryptionProperties node\n", 
	    func);	
#endif
	return(NULL);	
    }
    if(id != NULL) {
	xmlSetProp(encProps, BAD_CAST "Id", id);
    }
    
    return(encProps);
}

/** 
 * xmlSecEncDataAddEncProperty
 *
 *
 *
 */
xmlNodePtr	
xmlSecEncDataAddEncProperty(xmlNodePtr encNode, const xmlChar *id,  const xmlChar *target) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncDataAddEncProperty";
    xmlNodePtr encProp;
    xmlNodePtr encProps;
        
    if((encNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: template is null\n", 
	    func);	
#endif
	return(NULL);	        
    }

    encProps = xmlSecFindChild(encNode, BAD_CAST "EncryptionProperties", xmlSecEncNs);
    if(encProps == NULL) {
	encProps = xmlSecEncDataAddEncProperties(encNode, NULL);
	if(encProps == NULL) { 
#ifdef XMLSEC_DEBUG
            xmlGenericError(xmlGenericErrorContext,
		"%s: the EncryptionProperties node creatin failed\n", 
	        func);	
#endif
	    return(NULL);	
	}
    }

    encProp = xmlSecAddChild(encProps, BAD_CAST "EncryptionProperty", xmlSecEncNs);
    if(encProp == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create EncryptionProperty node\n", 
	    func);	
#endif
	return(NULL);	
    }
    if(id != NULL) {
	xmlSetProp(encProp, BAD_CAST "Id", id);
    }
    if(target != NULL) {
	xmlSetProp(encProp, BAD_CAST "Target", target);
    }
    
    return(encProp);
}

/** 
 * xmlSecEncDataAddCipherValue
 *
 *
 *
 */
xmlNodePtr
xmlSecEncDataAddCipherValue(xmlNodePtr encNode) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncDataAddCipherValue";
    xmlNodePtr cipherData;
    xmlNodePtr cipherValue;
    xmlNodePtr tmp;
        
    if((encNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: template is null\n", 
	    func);	
#endif
	return(NULL);	        
    }

    cipherData = xmlSecFindChild(encNode, BAD_CAST "CipherData", xmlSecEncNs);
    if(cipherData == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: CipherData node is not found\n", 
	    func);	
#endif
	return(NULL);	
    }

    tmp = xmlSecFindChild(cipherData, BAD_CAST "CipherValue", xmlSecEncNs);
    if(tmp != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: CipherValue node is already present\n", 
	    func);	
#endif
	return(NULL);	
    }

    tmp = xmlSecFindChild(cipherData, BAD_CAST "CipherReference", xmlSecEncNs);
    if(tmp != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: CipherReference node is already present\n", 
	    func);	
#endif
	return(NULL);	
    }

    cipherValue = xmlSecAddChild(cipherData, BAD_CAST "CipherValue", xmlSecEncNs);
    if(cipherValue == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create CipherValue node\n", 
	    func);	
#endif
	return(NULL);	
    }    
        
    return(cipherValue);
}

/** 
 * xmlSecEncDataAddCipherReference
 *
 *
 *
 */
xmlNodePtr
xmlSecEncDataAddCipherReference(xmlNodePtr encNode, const xmlChar *uri) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncDataAddCipherReference";
    xmlNodePtr cipherRef;
    xmlNodePtr cipherData;    
    xmlNodePtr tmp;
    
    if((encNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: template is null\n", 
	    func);	
#endif
	return(NULL);	        
    }

    cipherData = xmlSecFindChild(encNode, BAD_CAST "CipherData", xmlSecEncNs);
    if(cipherData == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: CipherData node is not found\n", 
	    func);	
#endif
	return(NULL);	
    }

    tmp = xmlSecFindChild(cipherData, BAD_CAST "CipherValue", xmlSecEncNs);
    if(tmp != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: CipherValue node is already present\n", 
	    func);	
#endif
	return(NULL);	
    }

    tmp = xmlSecFindChild(cipherData, BAD_CAST "CipherReference", xmlSecEncNs);
    if(tmp != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: CipherReference node is already present\n", 
	    func);	
#endif
	return(NULL);	
    }

    cipherRef = xmlSecAddChild(cipherData, BAD_CAST "CipherReference", xmlSecEncNs);
    if(cipherRef == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create CipherValue node\n", 
	    func);	
#endif
	return(NULL);	
    }    
    
    if(uri != NULL) {
	xmlSetProp(cipherRef, BAD_CAST "URI", uri);
    }
    
    return(cipherRef);
}

/** 
 * xmlSecCipherReferenceAddTransform
 *
 *
 *
 */
xmlNodePtr
xmlSecCipherReferenceAddTransform(xmlNodePtr encNode, xmlSecTransformId transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecCipherReferenceAddTransform";
    xmlNodePtr cipherData;
    xmlNodePtr cipherRef;    
    xmlNodePtr transforms;
    xmlNodePtr cipherRefTransform;
    int ret;
    
    if((encNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: template is null\n", 
	    func);	
#endif
	return(NULL);	        
    }

    cipherData = xmlSecFindChild(encNode, BAD_CAST "CipherData", xmlSecEncNs);
    if(cipherData == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: CipherData node is not found\n", 
	    func);	
#endif
	return(NULL);	
    }

    cipherRef = xmlSecFindChild(cipherData, BAD_CAST "CipherReference", xmlSecEncNs);
    if(cipherRef == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: CipherReference node is not found\n", 
	    func);	
#endif
	return(NULL);	
    }

    transforms = xmlSecFindChild(cipherRef, BAD_CAST "Transforms", xmlSecEncNs);
    if(transforms == NULL) {
	transforms = xmlSecAddChild(cipherRef, BAD_CAST "Transforms", xmlSecEncNs);
	if(transforms == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create Transforms node\n", 
		func);	
#endif
	    return(NULL);	
	}
    }
    
    cipherRefTransform = xmlSecAddChild(transforms,  BAD_CAST "Transform", xmlSecDSigNs);
    if(cipherRefTransform == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create Transform node\n", 
	    func);	
#endif
	return(NULL);	
    }
    
    ret = xmlSecTransformNodeWrite(cipherRefTransform, transform);
    if(ret < 0){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: enc method write failed\n", 
	    func);	
#endif
	return(NULL);	
    }
    
    return(cipherRefTransform);
}


/**
 * Encryption
 */

/**
 * xmlSecEncryptMemory
 *
 *
 *
 */
int
xmlSecEncryptMemory(xmlSecEncCtxPtr ctx, void *context, xmlSecKeyPtr key, 
		    xmlNodePtr encNode, const unsigned char *buf, size_t size,
		    xmlSecEncResultPtr *result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncryptMemory";
    xmlSecEncStatePtr state = NULL;
    xmlSecEncResultPtr res = NULL;
    int ret;
    
    if((ctx == NULL) || (encNode == NULL) || (buf == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: context, encNode or buff is null\n", 
	    func);	
#endif
	return(-1);	    
    }

    
    res = xmlSecEncResultCreate(ctx, context, 1, encNode);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create result object\n", 
	    func);	
#endif
	return(-1);	    		
    }
    if(key != NULL) {
	res->key = xmlSecKeyDuplicate(key, key->origin);    
    }
    

    /**
     * create state
     */    
    state = xmlSecEncStateCreate(ctx, encNode, 1, res);
    if(state == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create encryption state\n", 
	    func);	
#endif
	xmlSecEncResultDestroy(res);
	return(-1);	    
    }
         
    /* encrypt the data */
    ret = xmlSecBinTransformWrite((xmlSecTransformPtr)state->first, buf, size);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to encrypt the buffer\n", 
	    func);	
#endif
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }
    ret = xmlSecBinTransformFlush((xmlSecTransformPtr)state->first);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to finalize encryption\n", 
	    func);	
#endif
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }

    ret = xmlSecEncStateWriteResult(state, encNode, res); 			
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: finalization failed\n", 
	    func);	
#endif
	xmlSecEncStateDestroy(state);
	xmlSecEncResultDestroy(res); 
	return(-1);	    
    }
    
    /* cleanup */
    if(result != NULL) {
	(*result) = res;
    } else {
	xmlSecEncResultDestroy(res);
    }
    xmlSecEncStateDestroy(state);    
    return(0);
}

/**
 * xmlSecEncryptUri
 *
 *
 *
 */
int
xmlSecEncryptUri(xmlSecEncCtxPtr ctx, void *context, xmlSecKeyPtr key, 
		xmlNodePtr encNode, const char *uri, 
		xmlSecEncResultPtr *result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncryptUri";
    xmlSecEncStatePtr state = NULL;
    xmlSecEncResultPtr res = NULL;
    xmlSecTransformPtr inputUri = NULL;
    unsigned char buf[1024];
    int ret;

    if((ctx == NULL) || (encNode == NULL) || (uri == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: context, encNode or uri is null\n", 
	    func);	
#endif
	return(-1);	    
    }

    res = xmlSecEncResultCreate(ctx, context, 1, encNode);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create result object\n", 
	    func);	
#endif
	return(-1);	    		
    }
    if(key != NULL) {
	res->key = xmlSecKeyDuplicate(key, key->origin);    
    }

    /**
     * create state
     */    
    state = xmlSecEncStateCreate(ctx, encNode, 1, res);
    if(state == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create encryption state\n", 
	    func);	
#endif
	xmlSecEncResultDestroy(res);
	return(-1);	    
    }
    
    /* add the uri load at the beginning */
    inputUri = xmlSecTransformCreate(xmlSecInputUri, 0, 0);
    if(inputUri == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create uri transform\n",
	    func);
#endif	    
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	
    }    
    
    ret = xmlSecInputUriTransformOpen(inputUri, uri);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to open uri \"%s\"\n",
	    func, uri);
#endif	    
	xmlSecTransformDestroy(inputUri, 1);	
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	
    }
    
    ret = xmlSecEncStateAddFirstTransform(state, inputUri);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add uri transform\n",
	    func);
#endif	    
	xmlSecTransformDestroy(inputUri, 1);	
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	
    }
         
    /* encrypt the data */
    do {
	ret = xmlSecBinTransformRead((xmlSecTransformPtr)state->last, buf, sizeof(buf));
    } while(ret > 0);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to encrypt the buffer\n", 
	    func);	
#endif
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }

    ret = xmlSecEncStateWriteResult(state, encNode, res); 			
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: finalization failed\n", 
	    func);	
#endif
	xmlSecEncStateDestroy(state);
	xmlSecEncResultDestroy(res); 
	return(-1);	    
    }
    
    /* cleanup */
    if(result != NULL) {
	(*result) = res;
    } else {
	xmlSecEncResultDestroy(res);
    }
    xmlSecEncStateDestroy(state);    
    return(0);
}

/**
 * xmlSecEncryptXmlNode
 *
 *
 *
 */
int
xmlSecEncryptXmlNode(xmlSecEncCtxPtr ctx, void *context, xmlSecKeyPtr key, 
		    xmlNodePtr encNode, xmlNodePtr src, 
		    xmlSecEncResultPtr *result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncryptXmlNode";
    xmlSecEncStatePtr state = NULL;
    xmlSecEncResultPtr res = NULL;
    xmlBufferPtr buffer = NULL;
    int ret;

    if((ctx == NULL) || (encNode == NULL) || (src == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: context, encNode or src is null\n", 
	    func);	
#endif
	return(-1);	    
    }

    res = xmlSecEncResultCreate(ctx, context, 1, encNode);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create result object\n", 
	    func);	
#endif
	return(-1);	    		
    }
    if(key != NULL) {
	res->key = xmlSecKeyDuplicate(key, key->origin);    
    }

    /**
     * create state
     */    
    state = xmlSecEncStateCreate(ctx, encNode, 1, res);
    if(state == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create encryption state\n", 
	    func);	
#endif
	xmlSecEncResultDestroy(res);
	return(-1);	    
    }

    buffer = xmlBufferCreate();
    if(buffer == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: output buffer creation failed\n", 
	    func);	
#endif
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }
    
    /** 
     * read the stuff we need to encrypt into the buffer 
     */
    if(ctx->ignoreType || (res->type == NULL)) {
	/* get the content of the node */
	xmlNodeDump(buffer, src->doc, src, 0, 0);
    } else if(xmlStrEqual(res->type, xmlSecEncTypeElement)) {
	/* get the content of the node */
	xmlNodeDump(buffer, src->doc, src, 0, 0);
    } else if(xmlStrEqual(res->type, xmlSecEncTypeContent)) {
	xmlNodePtr ptr;
	/* get the content of the nodes childs */
	ptr = src->children;
	while(ptr != NULL) {
	    xmlNodeDump(buffer, ptr->doc, ptr, 0, 0); 
	    ptr = ptr->next;
	}
    } else {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: the type \"%s\" is unknown\n", 
	    func, res->type);	
#endif
	xmlBufferFree(buffer);
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }
        
    /* encrypt the data */
    ret = xmlSecBinTransformWrite((xmlSecTransformPtr)state->first, 
				  xmlBufferContent(buffer),
				  xmlBufferLength(buffer));
    xmlBufferFree(buffer); buffer = NULL;
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to encrypt the buffer\n", 
	    func);	
#endif
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }
    ret = xmlSecBinTransformFlush((xmlSecTransformPtr)state->first);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to finalize encryption\n", 
	    func);	
#endif
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }

    ret = xmlSecEncStateWriteResult(state, encNode, res); 			
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: finalization failed\n", 
	    func);	
#endif
	xmlSecEncStateDestroy(state);
	xmlSecEncResultDestroy(res); 
	return(-1);	    
    }
    
    if(!ctx->ignoreType && (res->type != NULL)) {
	if(xmlStrEqual(res->type, xmlSecEncTypeElement)) {
	    ret = xmlSecReplaceNode(src, encNode);
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: node replacement failed\n", 
		    func);	
#endif
		xmlSecEncStateDestroy(state);
		xmlSecEncResultDestroy(res); 
		return(-1);
	    }
	    res->replaced = 1;			       
	} else if(xmlStrEqual(res->type, xmlSecEncTypeContent)) {
	    ret = xmlSecReplaceContent(src, encNode);
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: content replacement failed\n", 
		    func);	
#endif
		xmlSecEncStateDestroy(state);
		xmlSecEncResultDestroy(res); 
		return(-1);
	    }
	    res->replaced = 1;			       
	} else {
	    /* do nothing: type is unknown */
	}
    }
    
    /* cleanup */
    if(result != NULL) {
	(*result) = res;
    } else {
	xmlSecEncResultDestroy(res);
    }
    xmlSecEncStateDestroy(state);    
    return(0);
}

/**
 * Decryption
 */
 
/**
 * xmlSecDecrypt
 *
 *
 *
 *
 */
int
xmlSecDecrypt(xmlSecEncCtxPtr ctx, void *context, xmlSecKeyPtr key, 
	     xmlNodePtr encNode, xmlSecEncResultPtr *result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDecrypt";
    xmlSecEncStatePtr state;
    xmlSecEncResultPtr res;
    int ret;
    
    if((ctx == NULL) || (encNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: context or encNode is null\n", 
	    func);	
#endif
	return(-1);	    
    }
    
    /* first of all, create result and encryption state objects */
    res = xmlSecEncResultCreate(ctx, context, 0, encNode);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create result object\n", 
	    func);	
#endif
	return(-1);	    		
    }
    if(key != NULL) {
	res->key = xmlSecKeyDuplicate(key, key->origin);    
    }

    state = xmlSecEncStateCreate(ctx, encNode, 0, res);
    if(state == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create encryption state\n", 
	    func);	
#endif
	xmlSecEncResultDestroy(res);
	return(-1);	    
    }
    
    if(state->cipherDataNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: CipherData node is not found\n", 
	    func);	
#endif
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    	
	return(-1);	    	
    }
    
    ret = xmlSecCipherDataNodeRead(state->cipherDataNode, state, res);
    if((ret < 0) || (res->buffer == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to get CipherData node content\n", 
	    func);	
#endif
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    	
	return(-1);	    	
    }
    
    if(!ctx->ignoreType && (res->type != NULL)) {
	if(xmlStrEqual(res->type, xmlSecEncTypeElement)) {
	    ret = xmlSecReplaceNodeBuffer(encNode, 
				    xmlBufferContent(res->buffer),  
				    xmlBufferLength(res->buffer));
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: failed to replace node\n", 
		    func);	
#endif
		xmlSecEncResultDestroy(res);
		xmlSecEncStateDestroy(state);    
		return(-1);	    	
	    }
	    res->replaced = 1;			       
	} else if(xmlStrEqual(res->type, xmlSecEncTypeContent)) {
	    /* replace the node with the buffer */
	    ret = xmlSecReplaceNodeBuffer(encNode, 
				       xmlBufferContent(res->buffer),
				       xmlBufferLength(res->buffer));
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: failed to replace content\n", 
		    func);	
#endif
		xmlSecEncResultDestroy(res);
		xmlSecEncStateDestroy(state);    
		return(-1);	    	
	    }	
	    res->replaced = 1;			       
	} else {
	    /* do nothing: type is unknown */
	}
    }
    
    /* cleanup */
    if(result != NULL) {
	(*result) = res;
    } else {
	xmlSecEncResultDestroy(res);
    }
    xmlSecEncStateDestroy(state);    
    return(0);
}
							 
/** 
 * XMLS Enc state
 */

/** 
 * xmlSecEncStateCreate
 *
 *
 *
 */ 
static xmlSecEncStatePtr
xmlSecEncStateCreate(xmlSecEncCtxPtr ctx, xmlNodePtr encNode, int encrypt, xmlSecEncResultPtr result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncStateCreate";
    xmlSecEncStatePtr state;
    int ret;

    if((ctx == NULL) || (encNode == NULL) || (result == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: encNode node, context or result is null\n", 
	    func);	
#endif
	return(NULL);
    }

    /*
     * Allocate a new xmlSecEncState and fill the fields.
     */
    state = (xmlSecEncStatePtr) xmlMalloc(sizeof(xmlSecEncState));
    if(state == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xmlSecEncState malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(state, 0, sizeof(xmlSecEncState));
        
    state->encrypt = encrypt;
    state->ctx = ctx;

    /*  read and update the Encryption Method and KeyInfo */
    ret = xmlSecEncryptedDataNodeRead(encNode, state, result);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to read EncryptedData\n", 
	    func);	
#endif
	xmlSecEncStateDestroy(state);
	return(NULL);	    	
    }

    return(state);
}

/** 
 * xmlSecEncStateDestroy
 *
 *
 *
 */ 
static void
xmlSecEncStateDestroy(xmlSecEncStatePtr state) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncStateDestroy";
    if(state == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: context is null\n", 
	    func);	
#endif
	return;	    
    }
    
    if(state->first != NULL) {
	xmlSecBinTransformDestroyAll((xmlSecTransformPtr)state->first);
    } else if(state->last != NULL) {
	xmlSecBinTransformDestroyAll((xmlSecTransformPtr)state->last);
    }
    
    memset(state, 0, sizeof(xmlSecEncState));
    xmlFree(state);
}

/**
 * xmlSecEncStateWriteResult
 *
 *
 *
 */
static int
xmlSecEncStateWriteResult(xmlSecEncStatePtr state, xmlNodePtr encNode,
		       xmlSecEncResultPtr result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncStateWriteResult";
    int ret;
    
    if((encNode == NULL) || (state == NULL) || (result == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: encNode, state or result is null\n", 
	    func);	
#endif
	return(-1);	    
    }

    /* update template */
    result->buffer = xmlSecMemBufTransformGetBuffer((xmlSecTransformPtr)state->last, 1);
    if(result->buffer == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to get memory buffer\n", 
	    func);	
#endif
	xmlSecEncResultDestroy(result);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }
    
    ret = xmlSecCipherDataNodeWrite(state->cipherDataNode, 
				xmlBufferContent(result->buffer), 
				xmlBufferLength(result->buffer));
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to write CipherData node\n", 
	    func);	
#endif
	xmlSecEncResultDestroy(result);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }
    return(0);
}

/**
 * xmlSecEncStateAddTransform
 *
 *
 *
 *
 */
static int
xmlSecEncStateAddTransform(xmlSecEncStatePtr state, xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncStateAddTransform";

    if((state == NULL) || !xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) { 
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: state is null or transform is invalid\n", 
	    func);	
#endif
	return(-1);	    
    }
    if(state->last == NULL) {
	state->first = state->last = (xmlSecBinTransformPtr)transform;
    } else if(xmlSecBinTransformAddAfter((xmlSecTransformPtr)state->last, 
					 transform) != NULL) {
	 state->last = (xmlSecBinTransformPtr)transform;
    } else {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add transform\n", 
	    func);	
#endif
	return(-1);	    
    }
    return(0);
}

/**
 * xmlSecEncStateAddFirstTransform
 *
 *
 *
 *
 */
static int
xmlSecEncStateAddFirstTransform(xmlSecEncStatePtr state, xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncStateAddFirstTransform";

    if((state == NULL) || !xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) { 
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: state is null or transform is invalid\n", 
	    func);	
#endif
	return(-1);	    
    }
    if(state->first == NULL) {
	state->first = state->last = (xmlSecBinTransformPtr)transform;
    } else if(xmlSecBinTransformAddBefore((xmlSecTransformPtr)state->first, 
					  transform) != NULL) {
	 state->first = (xmlSecBinTransformPtr)transform;
    } else {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add transform\n", 
	    func);	
#endif
	return(-1);	    
    }
    return(0);
}

/**
 * XML Enc Result
 */
/**
 * xmlSecEncResultCreate
 *
 *
 *
 *
 */ 		
xmlSecEncResultPtr		
xmlSecEncResultCreate(xmlSecEncCtxPtr ctx, void *context, int encrypt, xmlNodePtr node) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncResultCreate";
    xmlSecEncResultPtr result;
    
    if(ctx == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: context is null\n", 
	    func);	
#endif
	return(NULL);	    
    }
    
    /*
     * Allocate a new xmlSecEncResult and fill the fields.
     */
    result = (xmlSecEncResultPtr) xmlMalloc(sizeof(xmlSecEncResult));
    if(result == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xmlSecEncResult malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(result, 0, sizeof(xmlSecEncResult));
        
    result->ctx = ctx;
    result->self = node;
    result->encrypt = encrypt;
    result->context = context;
    return(result);
}

/**
 * xmlSecEncResultDestoy
 *
 *
 *
 *
 */ 		
void
xmlSecEncResultDestroy(xmlSecEncResultPtr result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncResultDestroy";
    if(result == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: result is null\n", 
	    func);	
#endif
	return;	    
    }
    
    if(result->key != NULL) {
	xmlSecKeyDestroy(result->key);
    }

    if(result->buffer != NULL) {
	xmlBufferEmpty(result->buffer);
	xmlBufferFree(result->buffer); 	
    }

    if(result->id != NULL) {
	xmlFree(result->id);
    }
    if(result->type != NULL) {
	xmlFree(result->type);
    }
    if(result->mimeType != NULL) {
	xmlFree(result->mimeType);
    }
    if(result->encoding != NULL) {
	xmlFree(result->encoding);
    }
    
    memset(result, 0, sizeof(xmlSecEncResult));
    xmlFree(result);
}


/**
 * xmlSecEncResultDebugDump
 *
 *
 *
 */
void
xmlSecEncResultDebugDump(xmlSecEncResultPtr result, FILE *output) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncResultDebugDump";

    if(result == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: result is null\n", 
	    func);	
#endif
	return;	    
    }

    if(result->encrypt) {    
        fprintf(output, "= ENCRYPTION RESULT\n");
    } else {
        fprintf(output, "= DECRYPTION RESULT (%s)\n",
	    (result->replaced) ? "replaced" : "not-replaced" );
    }
    if(result->id != NULL) {
	fprintf(output, "== Id: \"%s\"\n", result->id);
    }
    if(result->type != NULL) {
	fprintf(output, "== Type: \"%s\"\n", result->type);
    }
    if(result->mimeType != NULL) {
	fprintf(output, "== MimeType: \"%s\"\n", result->mimeType);
    }
    if(result->encoding != NULL) {
	fprintf(output, "== Encoding: \"%s\"\n", result->encoding);
    }
    
    if(result->key != NULL) {
	xmlSecKeyDebugDump(result->key, output);
    }

    if(result->buffer != NULL) {
	fprintf(output, "== start buffer:\n");
	fwrite(xmlBufferContent(result->buffer), 
	       xmlBufferLength(result->buffer), 1,
	       output);
	fprintf(output, "\n== end buffer\n");
    }	    

}


/**
 * xmlSecEncryptedDataNodeRead
 *
 *
 */
static int
xmlSecEncryptedDataNodeRead(xmlNodePtr encNode, xmlSecEncStatePtr state, xmlSecEncResultPtr result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncryptedDataNodeRead";
    xmlNodePtr cur;
    xmlNodePtr keyInfoNode = NULL;
    xmlSecTransformPtr encryptionMethod = NULL;
    int ret;
    
    if((state == NULL) || (encNode == NULL) || (result == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: state or encNode node is null\n", 
	    func);	
#endif
	return(-1);	    
    }

    result->id = xmlGetProp(encNode, BAD_CAST "Id");
    result->type = xmlGetProp(encNode, BAD_CAST "Type");
    result->mimeType = xmlGetProp(encNode, BAD_CAST "MimeType");
    result->encoding = xmlGetProp(encNode, BAD_CAST "Encoding");
    cur = xmlSecGetNextElementNode(encNode->children);    
        
    /* first node is optional EncryptionMethod */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "EncryptionMethod", xmlSecEncNs))) {
	encryptionMethod = xmlSecTransformNodeRead(cur, xmlSecUsageEncryptionMethod, 0);
	cur = xmlSecGetNextElementNode(cur->next);
    } else if((state->ctx != NULL) && (state->ctx->encryptionMethod != xmlSecTransformUnknown)){
	/* get encryption method from the context */
	encryptionMethod = xmlSecTransformCreate(state->ctx->encryptionMethod,
						xmlSecUsageEncryptionMethod, 0);
    } else {
#ifdef XMLSEC_DEBUG
	 xmlGenericError(xmlGenericErrorContext,
	    "%s: EncryptionMethod not specified\n",
	    func);
#endif		
	return(-1);
    }
    if(encryptionMethod == NULL) {
#ifdef XMLSEC_DEBUG
         xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to read or create EncryptionMethod\n",
	    func);
#endif		
	return(-1);
    }    
    ret = xmlSecEncStateAddTransform(state, encryptionMethod);
    if(ret < 0) {    
#ifdef XMLSEC_DEBUG
         xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to add EncryptionMethod\n",
	    func);
#endif		
	xmlSecTransformDestroy(encryptionMethod, 1); 
	return(-1);
    }
    xmlSecBinTransformSetEncrypt(encryptionMethod, state->encrypt);
    result->encryptionMethod = encryptionMethod->id;
    
    /* next node is optional KeyInfo */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "KeyInfo", xmlSecDSigNs))) {
	keyInfoNode = cur;
	cur = xmlSecGetNextElementNode(cur->next);
    }    

    /* now we are ready to get key, KeyInfo node may be NULL! */
    if((result->key == NULL) && (xmlSecEncResultGetKeyCallback(result) != NULL)) {
        xmlSecKeyId keyId;
        xmlSecKeyType keyType;    
        xmlSecKeyUsage keyUsage;

	if(result->encrypt) {
	    keyType = xmlSecBinTransformIdGetEncKeyType(result->encryptionMethod);
	    keyUsage = xmlSecKeyUsageEncrypt;
	} else {
	    keyType = xmlSecBinTransformIdGetDecKeyType(result->encryptionMethod);
	    keyUsage = xmlSecKeyUsageDecrypt;
	}
	keyId = xmlSecBinTransformIdGetKeyId(result->encryptionMethod);
		
	result->key = xmlSecEncResultGetKeyCallback(result)
					(keyInfoNode, result->ctx->keysMngr, 
					result->context, keyId, keyType, 
					keyUsage); 
    }    
    if(result->key == NULL) {
#ifdef XMLSEC_DEBUG    
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to find encryption key\n",
	    func);
#endif	    
	return(-1);
    }
    ret = xmlSecTransformAddKey(encryptionMethod, result->key);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG    
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to add key\n",
	    func);
#endif	    
	return(-1);
    }
    if(result->encrypt && (keyInfoNode != NULL)) {
	/* update KeyInfo! */
	ret = xmlSecKeyInfoNodeWrite(keyInfoNode, 
			result->ctx->keysMngr, result->context,
		    	result->key, 
			xmlSecBinTransformIdGetDecKeyType(result->encryptionMethod));
	if(ret < 0) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
	        "%s: failed to write \"KeyInfo\"\n",
	        func);
#endif	    
	    return(-1);
	}	
    }

    /* next is required CipherData node */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "CipherData", xmlSecEncNs))) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"CipherData\" missed\n",
	    func);
#endif	    	
	return(-1);
    }
    state->cipherDataNode = cur;
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is optional EncryptionProperties node (we simply ignore it) */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "EncryptionProperties", xmlSecEncNs))) {
	cur = xmlSecGetNextElementNode(cur->next);
    }

    if(state->encrypt == 1) {
	xmlSecTransformPtr memBuf = NULL;	
	xmlSecTransformPtr base64;
	/* last transform for encryption is base64 encode */
	
	base64 = xmlSecTransformCreate(xmlSecEncBase64Encode, 0, 0);
	if(base64 == NULL) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create base64 encode transform\n",
		func);
#endif	    	
	    return(-1);
	}
	ret = xmlSecEncStateAddTransform(state, base64);
	if(ret < 0) {    
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
    		"%s: failed to add Base64 encrypt\n",
		func);
#endif		
	    xmlSecTransformDestroy(base64, 1); 
	    return(-1);
	}
	
	/* add mem buf at the end */
	memBuf = xmlSecTransformCreate(xmlSecMemBuf, 0, 0);
	if(memBuf == NULL) {
#ifdef XMLSEC_DEBUG    
    	    xmlGenericError(xmlGenericErrorContext,
    		"%s: failed to create memBuf encode transform\n",
		func);
#endif	    	
	    return(-1);
	}
	ret = xmlSecEncStateAddTransform(state, memBuf);
        if(ret < 0) {    
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
    		"%s: failed to add Base64 encrypt\n",
		func);
#endif		
	    xmlSecTransformDestroy(memBuf, 1); 
	    return(-1);
	}
    }

/*    
    TODO: add support for other nodes
    if(cur != NULL) {
#ifdef XMLSEC_DEBUG
	 xmlGenericError(xmlGenericErrorContext,
	    "%s: unexpected node found\n",
	    func);
#endif		
	return(-1);
    }
*/        
    return(0);
}



static int
xmlSecCipherDataNodeRead(xmlNodePtr cipherDataNode, xmlSecEncStatePtr state, 
			 xmlSecEncResultPtr result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecCipherDataNodeRead";
    xmlNodePtr cur;
    int ret;
    
    if((state == NULL) || (cipherDataNode == NULL) || (result == NULL)){
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: state, node or ctx is null\n",
	    func);
#endif	    
	return(-1);
    }
    
    cur = xmlSecGetNextElementNode(cipherDataNode->children);

    /* CipherValue or CipherReference */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "CipherValue", xmlSecEncNs))) {
	ret = xmlSecCipherValueNodeRead(cur, state, result);
	if(ret < 0){
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to read CipherValue node\n",
		func);
#endif	    
	    return(-1);
	}
	cur = xmlSecGetNextElementNode(cur->next);	
    } else if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "CipherReference",  xmlSecEncNs))) { 
	ret = xmlSecCipherReferenceNodeRead(cur, state, result);
	if(ret < 0){
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to read CipherReference node\n",
		func);
#endif	    
	    return(-1);
	}
	cur = xmlSecGetNextElementNode(cur->next);	
    }

    if(cur != NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: found unexpected node \"%s\"\n",
	    func, cur->name);
#endif	    
	return(-1);
    }
    return(0);
}


/**
 * xmlSecCipherDataNodeWrite
 *
 *
 *
 *
 */
static int
xmlSecCipherDataNodeWrite(xmlNodePtr cipherDataNode,
		      const unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED ="xmlSecCipherDataNodeWrite";
    xmlNodePtr cur; 

    if((cipherDataNode == NULL) || (buf == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: cipherDataNode or buf is null\n", 
	    func);	
#endif
	return(-1);	    
    }

    cur = xmlSecGetNextElementNode(cipherDataNode->children);
    if(cur == NULL) {
	cur = xmlSecAddChild(cipherDataNode, BAD_CAST "CipherValue", xmlSecEncNs);
	if(cur == NULL) {
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
	        "%s: failed to create CipherValue node\n", 
		func);	
#endif
	    return(-1);	    	    
	}
        xmlNodeSetContent(cur, BAD_CAST "\n");
	xmlNodeAddContentLen(cur, buf, size);
        xmlNodeAddContent(cur, BAD_CAST "\n");
	return(0);
    } else if(xmlSecCheckNodeName(cur, BAD_CAST "CipherValue", xmlSecEncNs)) {
        xmlNodeSetContent(cur, BAD_CAST "\n");
	xmlNodeAddContentLen(cur, buf, size);
        xmlNodeAddContent(cur, BAD_CAST "\n");
	cur = xmlSecGetNextElementNode(cur->next);
    } else if(xmlSecCheckNodeName(cur, BAD_CAST "CipherReference", xmlSecEncNs)) {
	/* do nothing! */
	cur = xmlSecGetNextElementNode(cur->next);
    }
    if(cur != NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: found unexpected node \"%s\"\n",
	    func, cur->name);
#endif	    
	return(-1);
    }
    return(0);
}


static int
xmlSecCipherValueNodeRead(xmlNodePtr cipherValueNode, xmlSecEncStatePtr state, 
			  xmlSecEncResultPtr result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecCipherValueNodeRead";
    xmlSecTransformPtr base64;
    xmlSecTransformPtr memBuf;
    xmlChar *content;
    int ret;
    
    if((state == NULL) || (cipherValueNode == NULL) || (result == NULL)){
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: state, node or ctx is null\n",
	    func);
#endif	    
	return(-1);
    }

    /* first transform for decryption is base64 decode */	
    base64 = xmlSecTransformCreate(xmlSecEncBase64Decode, 0, 0);
    if(base64 == NULL) {
#ifdef XMLSEC_DEBUG    
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to create base64 dencode transform\n",
	    func);
#endif	    	
	return(-1);
    }

    ret = xmlSecEncStateAddFirstTransform(state, base64);
    if(ret < 0) {    
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to add Base64 decode\n",
	    func);
#endif		
	xmlSecTransformDestroy(base64, 1); 
	return(-1);
    }


    /* add mem buf at the end */
    memBuf = xmlSecTransformCreate(xmlSecMemBuf, 0, 0);
    if(memBuf == NULL) {
#ifdef XMLSEC_DEBUG    
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to create memBuf encode transform\n",
	    func);
#endif	    	
	return(-1);
    }
    ret = xmlSecEncStateAddTransform(state, memBuf);
    if(ret < 0) {    
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to add Base64 encrypt\n",
	    func);
#endif		
	xmlSecTransformDestroy(memBuf, 1); 
	return(-1);
    }


    /* get node content */
    content = xmlNodeGetContent(cipherValueNode);
    if(content == NULL) {
#ifdef XMLSEC_DEBUG    
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to get node content\n",
	    func);
#endif	    	
	return(-1);
    }
	
    /* decrypt the data */
    ret = xmlSecBinTransformWrite((xmlSecTransformPtr)state->first, 
				  content, xmlStrlen(content));
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to decrypt the data\n", 
	    func);	
#endif
	xmlFree(content);
	return(-1);	    	
    }
	
    /* flush everything */
    ret = xmlSecBinTransformFlush((xmlSecTransformPtr)state->first);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to finalize encryption\n", 
    	    func);	
#endif
	xmlFree(content);
        return(-1);	    	
    }

    result->buffer = xmlSecMemBufTransformGetBuffer((xmlSecTransformPtr)state->last, 1);
    if(result->buffer == NULL) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to get buffer\n", 
    	    func);	
#endif
	xmlFree(content);
        return(-1);	    	
    }
    
    xmlFree(content);
    return(0);
}

static int			
xmlSecCipherReferenceNodeRead(xmlNodePtr cipherReferenceNode, xmlSecEncStatePtr state, 
			      xmlSecEncResultPtr result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecCipherReferenceNodeRead";
    xmlSecBinTransformPtr transform;
    xmlSecTransformStatePtr transState = NULL;
    xmlNodePtr cur;
    xmlChar *uri = NULL;
    int res = -1;
    int ret;
    
    if((state == NULL) || (cipherReferenceNode == NULL) || (result == NULL)){
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: state, cipherReferenceNode or ctx is null\n",
	    func);
#endif	    
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cipherReferenceNode->children); 
    
    uri = xmlGetProp(cipherReferenceNode, BAD_CAST "URI");
    transState = xmlSecTransformStateCreate(cipherReferenceNode->doc, NULL, (char*)uri);
    if(transState == NULL){
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create transforms state\n",
	    func);
#endif	    
	goto done;
    }	
    
    /* first is optional Transforms node */
    if((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "Transforms", xmlSecEncNs)) {
	ret = xmlSecTransformsNodeRead(transState, cur);
	if(ret < 0){
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to read \"Transforms\"\n",
		func);
#endif	    
	    goto done;
	}	
	cur = xmlSecGetNextElementNode(cur->next);
    }
    if(cur != NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: found unexpected node\n",
	    func);
#endif	    
	goto done;
    }

    /* copy all transforms from encryption state to transform state */
    while(state->first != NULL) {
	transform = state->first;
	state->first = state->first->next;
	transform->next = NULL;
	if(state->first != NULL) {
	    state->first->prev = NULL;
	}
	
	ret = xmlSecTransformStateUpdate(transState, (xmlSecTransformPtr)transform);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: found unexpected node\n",
		func);
#endif	    
	    xmlSecBinTransformDestroyAll((xmlSecTransformPtr)transform);
	    goto done;
	}
    }
    state->last = NULL;
    ret = xmlSecTransformStateFinal(transState, xmlSecTransformResultBinary);
    if((ret < 0) || (transState->curBuf == NULL)){
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to finalize transforms\n",
	    func);
#endif
	goto done;
    }
    result->buffer = transState->curBuf;
    transState->curBuf = NULL;
    
    res = 0;
done:
    if(uri != NULL) {
	xmlFree(uri);
    }
    if(transState != NULL) {
	xmlSecTransformStateDestroy(transState);
    }
    return(res);
}

#endif /* XMLSEC_NO_XMLENC */

