/** 
 * XMLSec library
 *
 * "XML Digital Signature" implementation
 *  http://www.w3.org/TR/xmldsig-core/
 *  http://www.w3.org/Signature/Overview.html
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_XMLDSIG

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/parser.h> 

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/digests.h>
#include <xmlsec/membuf.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/errors.h>

#define xmlSecDSigResultGetKeyCallback(result) \
	    ( ( ((result) != NULL) && \
	        ((result)->ctx != NULL) && \
		((result)->ctx->keyInfoCtx.keysMngr != NULL) ) ? \
		((result)->ctx->keyInfoCtx.keysMngr->getKey) : \
		NULL )


static xmlSecReferenceResultPtr	xmlSecDSigResultAddSignedInfoRef(xmlSecDSigResultPtr result,
								 xmlSecReferenceResultPtr ref);
static xmlSecReferenceResultPtr	xmlSecDSigResultAddManifestRef	(xmlSecDSigResultPtr result,
								 xmlSecReferenceResultPtr ref);
static int			xmlSecSignatureRead		(xmlNodePtr signNode,
								 int sign,
								 xmlSecDSigResultPtr result);
static int			xmlSecSignedInfoRead		(xmlNodePtr signedInfoNode,
								 int sign,
								 xmlNodePtr signatureValueNode,
								 xmlNodePtr keyInfoNode,
								 xmlSecDSigResultPtr result);
static int			xmlSecSignedInfoCalculate	(xmlNodePtr signedInfoNode,
								 int sign,
								 xmlSecTransformPtr c14nMethod, 
								 xmlSecTransformPtr signMethod, 
								 xmlNodePtr signatureValueNode,
								 xmlSecDSigResultPtr result);

static xmlSecReferenceResultPtr	xmlSecReferenceCreate		(xmlSecReferenceType type,
								 xmlSecDSigCtxPtr ctx,
    								 xmlNodePtr self);
static int 			xmlSecReferenceRead		(xmlSecReferenceResultPtr ref,
    								 xmlNodePtr self,
								 int sign);
static void			xmlSecReferenceDestroy		(xmlSecReferenceResultPtr ref);
static void			xmlSecReferenceDestroyAll	(xmlSecReferenceResultPtr ref);
static void			xmlSecDSigReferenceDebugDump	(xmlSecReferenceResultPtr ref,
								 FILE *output);
static void			xmlSecDSigReferenceDebugXmlDump (xmlSecReferenceResultPtr ref,
								 FILE *output);
static void			xmlSecDSigReferenceDebugDumpAll	(xmlSecReferenceResultPtr ref,
								 FILE *output);
static void			xmlSecDSigReferenceDebugXmlDumpAll(xmlSecReferenceResultPtr ref,
								 FILE *output);

static int			xmlSecObjectRead		(xmlNodePtr objectNode,
								 int sign,
								 xmlSecDSigResultPtr result);
static int			xmlSecManifestRead		(xmlNodePtr manifestNode,
								 int sign,
								 xmlSecDSigResultPtr result);


/* The ID attribute in XMLDSig is 'Id' */
static const xmlChar*		xmlSecDSigIds[] = { BAD_CAST "Id", NULL };


/**************************************************************************
 *
 * XML DSig generation/validation functions
 *
 **************************************************************************/
/**
 * xmlSecDSigValidate:
 * @ctx: the pointer to #xmlSecDSigCtx structure.
 * @context: the pointer to application specific data that will be 
 *     passed to all callback functions.
 * @key: the key to use (if NULL then the key specified in <dsig:KeyInfo>
 *     will be used).   
 * @signNode: the pointer to <dsig:Signature> node that will be validated.
 * @result: the pointer where to store validation results.
 *
 * Validates the signature in @signNode and stores the pointer to validation 
 * result structure #xmlSecDSigResult in the @result. 
 *
 * Returns 0 if there were no processing errors during validation or a negative
 * value otherwise. The return value equal to 0 DOES NOT mean that the signature
 * is valid: check the #result member of #xmlSecDSigResult structure instead.
 */
int
xmlSecDSigValidate(xmlSecDSigCtxPtr ctx, void *context, xmlSecKeyPtr key,
		   xmlNodePtr signNode, xmlSecDSigResultPtr *result) {
    xmlSecDSigResultPtr res;    
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(signNode != NULL, -1);
    xmlSecAssert2(result != NULL, -1);

    (*result) = NULL;    
    if(!xmlSecCheckNodeName(signNode, BAD_CAST "Signature", xmlSecDSigNs)) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "Signature");
	return(-1);	    
    }
    
    /* add ids for Signature nodes */
    xmlSecAddIDs(signNode->doc, signNode, xmlSecDSigIds);
    
    res = xmlSecDSigResultCreate(ctx, context, signNode, 0);
    if(res == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDSigResultCreate");
	return(-1);
    }

    if(key != NULL) {
	res->key = xmlSecKeyDuplicate(key);    
    }

    ret = xmlSecSignatureRead(signNode, 0, res);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecSignatureRead - %d", ret);
        xmlSecDSigResultDestroy(res);
	return(-1);	    		
    }

    /* set result  */
    (*result) = res;
    return(0);
}

/**
 * xmlSecDSigGenerate
 * @ctx: the pointer to #xmlSecDSigCtx structure.
 * @context: the pointer to application specific data that will be 
 *     passed to all callback functions.
 * @key: the key to use (if NULL then the key specified in <dsig:KeyInfo>
 *     will be used).   
 * @signNode: the pointer to <dsig:Signature> template node.
 * @result: the pointer where to store signature results.
 *
 * Signs the data according to the template in @signNode node.
 *
 * Returns 0 on success and a negative value otherwise.
 */
int
xmlSecDSigGenerate(xmlSecDSigCtxPtr ctx, void *context, xmlSecKeyPtr key,
		   xmlNodePtr signNode, xmlSecDSigResultPtr *result) {
    xmlSecDSigResultPtr res;
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(signNode != NULL, -1);
    xmlSecAssert2(result != NULL, -1);

    (*result) = NULL;
    
    if(!xmlSecCheckNodeName(signNode, BAD_CAST "Signature", xmlSecDSigNs)) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "Signature");
	return(-1);	    
    }

    /* add ids for Signature nodes */
    xmlSecAddIDs(signNode->doc, signNode, xmlSecDSigIds);

    
    res = xmlSecDSigResultCreate(ctx, context, signNode, 1);
    if(res == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDSigResultCreate");
	return(-1);
    }

    if(key != NULL) {
	res->key = xmlSecKeyDuplicate(key);    
    }
    
    ret = xmlSecSignatureRead(signNode, 1, res);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecSignatureRead - %d", ret);
        xmlSecDSigResultDestroy(res);
	return(-1);	    		
    }

    /* set result  */
    (*result) = res;
    return(0);
}

/****************************************************************************
 *
 *   DSig result methods
 *
 ****************************************************************************/
/**
 * xmlSecDSigResultCreate:
 * @ctx: the pointer to #xmlSecDSigCtx structure.
 * @context: the pointer to application specific data that will be 
 *     passed to all callback functions.
 * @signNode: the pointer to <dsig:Signature> node that will be validated.
 * @sign: the sign or verify flag.
 * 
 * Creates new #xmlSecDSigResult structure.
 *
 * Returns newly created #xmlSecDSigResult structure or NULL 
 * if an error occurs.
 */
xmlSecDSigResultPtr	
xmlSecDSigResultCreate(xmlSecDSigCtxPtr ctx, void *context, 
		       xmlNodePtr signNode, int sign) {
    xmlSecDSigResultPtr result;
    
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(signNode != NULL, NULL);

    /* Allocate a new xmlSecSignature and fill the fields */
    result = (xmlSecDSigResultPtr) xmlMalloc(sizeof(xmlSecDSigResult));
    if(result == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecDSigResult)=%d",
		    sizeof(xmlSecDSigResult));
	return(NULL);
    }
    memset(result, 0, sizeof(xmlSecDSigResult));
    
    result->ctx = ctx;
    result->self = signNode;
    result->sign = sign;
    result->context = context;
    return(result);
}


/**
 * xmlSecDSigResultDestroy:
 * @result: the pointer to #xmlSecDSigResult structure.
 *
 * Destroys the #xmlSecDSigResult structure @result.
 */
void
xmlSecDSigResultDestroy(xmlSecDSigResultPtr result) {
    xmlSecAssert(result != NULL);

    /* destroy firstSignRef if needed */
    if(result->firstSignRef != NULL) {
	xmlSecReferenceDestroyAll(result->firstSignRef);
    }

    /* destroy firstManifestRef if needed */
    if(result->firstManifestRef != NULL) {
	xmlSecReferenceDestroyAll(result->firstManifestRef);
    }

    /* destroy buffer */
    if(result->buffer != NULL) {
	xmlSecBufferDestroy(result->buffer);     
    }
    if(result->key != NULL) {
	xmlSecKeyDestroy(result->key);
    }
    memset(result, 0, sizeof(xmlSecDSigResult));
    xmlFree(result);
}

/** 
 * xmlSecDSigResultDebugDump:
 * @result: the pointer to #xmlSecDSigResult structure.
 * @output: the pointer to destination FILE.
 *
 * Prints the #xmlSecDSigResult structure @result to file @output.
 */
void
xmlSecDSigResultDebugDump(xmlSecDSigResultPtr result, FILE *output) {

    xmlSecAssert(result != NULL);
    xmlSecAssert(output != NULL);
    
    fprintf(output, "= XMLDSig Result (%s)\n", 
	    (result->sign) ? "generate" : "validate");
    fprintf(output, "== result: %s\n", 
	    (result->result == xmlSecTransformStatusOk) ? "OK" : "FAIL");    
    fprintf(output, "== sign method: %s\n", 
	    (result->signMethod != NULL) ? 
	    (char*)((result->signMethod)->href) : "NULL"); 
    if(result->key != NULL) {
	xmlSecKeyDebugDump(result->key, output);
    }
    if(result->buffer != NULL) {
	fprintf(output, "== start buffer:\n");
	fwrite(xmlSecBufferGetData(result->buffer), 
	       xmlSecBufferGetSize(result->buffer), 1,
	       output);
	fprintf(output, "\n== end buffer\n");
    }	    
    
    /* print firstSignRef */
    if(result->firstSignRef != NULL) {
	fprintf(output, "== SIGNED INFO REFERENCES\n");
	xmlSecDSigReferenceDebugDumpAll(result->firstSignRef, output);
    }

    /* print firstManifestRef */
    if(result->firstManifestRef != NULL) {
	fprintf(output, "== MANIFESTS REFERENCES\n");
	xmlSecDSigReferenceDebugDumpAll(result->firstManifestRef, output);
    }
}

/** 
 * xmlSecDSigResultDebugXmlDump:
 * @result: the pointer to #xmlSecDSigResult structure.
 * @output: the pointer to destination FILE.
 *
 * Prints the #xmlSecDSigResult structure @result to file @output in XML format.
 */
void
xmlSecDSigResultDebugXmlDump(xmlSecDSigResultPtr result, FILE *output) {

    xmlSecAssert(result != NULL);
    xmlSecAssert(output != NULL);
    
    fprintf(output, "<DSigResult operation=\"%s\">\n", 
	    (result->sign) ? "generate" : "validate");
    fprintf(output, "<Status>%s</Status>\n", 
	    (result->result == xmlSecTransformStatusOk) ? "OK" : "FAIL");    
    fprintf(output, "<SignatureMethod>%s</SignatureMethod>\n", 
	    (result->signMethod != NULL) ? 
	    (char*)((result->signMethod)->href) : "NULL"); 
    if(result->key != NULL) {
	xmlSecKeyDebugXmlDump(result->key, output);
    }
    if(result->buffer != NULL) {
	fprintf(output, "<SignatureBuffer>");
	fwrite(xmlSecBufferGetData(result->buffer), 
	       xmlSecBufferGetSize(result->buffer), 1,
	       output);
	fprintf(output, "</SignatureBuffer>\n");
    }	    
    
    /* print firstSignRef */
    if(result->firstSignRef != NULL) {
	fprintf(output, "<SignedInfoReferences>\n");
	xmlSecDSigReferenceDebugXmlDumpAll(result->firstSignRef, output);
	fprintf(output, "</SignedInfoReferences>\n");
    }

    /* print firstManifestRef */
    if(result->firstManifestRef != NULL) {
	fprintf(output, "<ManifestReferences>\n");
	xmlSecDSigReferenceDebugXmlDumpAll(result->firstManifestRef, output);
	fprintf(output, "</ManifestReferences>\n");
    }
    fprintf(output, "</DSigResult>\n");
}


static xmlSecReferenceResultPtr
xmlSecDSigResultAddSignedInfoRef(xmlSecDSigResultPtr result, 
				 xmlSecReferenceResultPtr ref) {
    xmlSecAssert2(result != NULL, NULL);
    xmlSecAssert2(result->ctx != NULL, NULL);
    xmlSecAssert2(ref != NULL, NULL);
    
    /* add to the list */
    ref->prev = result->lastSignRef;
    if(result->lastSignRef != NULL) {
        result->lastSignRef->next = ref;
    }
    result->lastSignRef = ref;
    if(result->firstSignRef == NULL) {
	result->firstSignRef = ref;
    }
    return(ref);
}

static xmlSecReferenceResultPtr
xmlSecDSigResultAddManifestRef(xmlSecDSigResultPtr result, xmlSecReferenceResultPtr ref) {
    xmlSecAssert2(result != NULL, NULL);
    xmlSecAssert2(result->ctx != NULL, NULL);
    xmlSecAssert2(ref != NULL, NULL);
    
    /* add to the list */
    ref->prev = result->lastManifestRef;
    if(result->lastManifestRef != NULL) {
        result->lastManifestRef->next = ref;
    }
    result->lastManifestRef = ref;
    if(result->firstManifestRef == NULL) {
	result->firstManifestRef = ref;
    }
    return(ref);
}

							 
/**************************************************************************
 *
 * XML DSig context methods
 *
 **************************************************************************/
/**
 * xmlSecDSigCtxCreate:
 *
 * Creates new #xmlSecDSigCtx structure.
 *
 * Returns pointer to newly allocated #xmlSecDSigCtx structure or NULL
 * if an error occurs.
 */
xmlSecDSigCtxPtr		
xmlSecDSigCtxCreate(xmlSecKeysMngrPtr keysMngr) {
    xmlSecDSigCtxPtr ctx;
    
    /*
     * Allocate a new xmlSecDSigCtx and fill the fields.
     */
    ctx = (xmlSecDSigCtxPtr) xmlMalloc(sizeof(xmlSecDSigCtx));
    if(ctx == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecDSigCtx)=%d",
		    sizeof(xmlSecDSigCtx));
	return(NULL);
    }
    memset(ctx, 0, sizeof(xmlSecDSigCtx));
    
    /* by default we process Manifests and store everything */
    ctx->keyInfoCtx.keysMngr = keysMngr;
    ctx->processManifests = 1;
    ctx->storeSignatures = 1;
    ctx->storeReferences = 1;
    ctx->storeManifests = 1;
    return(ctx);
}

/**
 * xmlSecDSigCtxDestroy:
 * @ctx: the pointer to #xmlSecDSigCtx structure.
 *
 * Destroys #xmlSecDSigCtx structure @ctx.
 */
void
xmlSecDSigCtxDestroy(xmlSecDSigCtxPtr ctx) {    
    xmlSecAssert(ctx != NULL);

    memset(ctx, 0, sizeof(xmlSecDSigCtx));
    xmlFree(ctx);
}



/**
 * xmlSecSignatureRead:
 *
 * The Signature  element (http://www.w3.org/TR/xmldsig-core/#sec-Signature)
 *
 * The Signature element is the root element of an XML Signature. 
 * Implementation MUST generate laxly schema valid [XML-schema] Signature 
 * elements as specified by the following schema:
 *
 * Schema Definition:
 *
 *  <element name="Signature" type="ds:SignatureType"/>
 *  <complexType name="SignatureType">
 *  <sequence> 
 *     <element ref="ds:SignedInfo"/> 
 *     <element ref="ds:SignatureValue"/> 
 *     <element ref="ds:KeyInfo" minOccurs="0"/> 
 *     <element ref="ds:Object" minOccurs="0" maxOccurs="unbounded"/> 
 *     </sequence> <attribute name="Id" type="ID" use="optional"/>
 *  </complexType>
 *    
 * DTD:
 *    
 *  <!ELEMENT Signature (SignedInfo, SignatureValue, KeyInfo?, Object*)  >
 *  <!ATTLIST Signature  
 *      xmlns   CDATA   #FIXED 'http://www.w3.org/2000/09/xmldsig#'
 *      Id      ID  #IMPLIED >
 *
 */
static int			
xmlSecSignatureRead(xmlNodePtr signNode, int sign, xmlSecDSigResultPtr result) {
    xmlNodePtr signedInfoNode;
    xmlNodePtr signatureValueNode;
    xmlNodePtr keyInfoNode;
    xmlNodePtr firstObjectNode;
    xmlNodePtr cur;
    int ret;
    
    xmlSecAssert2(result != NULL, -1);
    xmlSecAssert2(result->ctx != NULL, -1);
    xmlSecAssert2(signNode != NULL, -1);
    
    cur = xmlSecGetNextElementNode(signNode->children);
    
    /* first node is required SignedInfo */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "SignedInfo", xmlSecDSigNs))) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "SignedInfo");
        return(-1);
    }
    signedInfoNode = cur;
    cur = xmlSecGetNextElementNode(cur->next);

    /* next node is required SignatureValue */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "SignatureValue", xmlSecDSigNs))) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "SignatureValue");
	return(-1);
    }
    signatureValueNode = cur;
    cur = xmlSecGetNextElementNode(cur->next);

    /* next node is optional KeyInfo */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "KeyInfo", xmlSecDSigNs))) {
	keyInfoNode = cur;
	cur = xmlSecGetNextElementNode(cur->next);
    } else{
	keyInfoNode = NULL;
    }

    
    /* next nodes are optional Object */
    firstObjectNode = NULL;
    while((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "Object", xmlSecDSigNs))) {
	if(firstObjectNode == NULL) {
	    firstObjectNode = cur;
	}

	/* read manifests from objects */
	if(result->ctx->processManifests) {
	    ret = xmlSecObjectRead(cur, sign, result);
	    if(ret < 0) {
    		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecObjectRead - %d", ret);
		return(-1);	    	    
	    }
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    if(cur != NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    (cur->name != NULL) ? (char*)cur->name : "NULL");
	return(-1);
    }

    /* now we are ready to read SignedInfo node and calculate/verify result */
    ret = xmlSecSignedInfoRead(signedInfoNode, sign, signatureValueNode, 
				keyInfoNode, result);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecSignedInfoRead - %d", ret);
	return(-1);	
    }				
    
    return(0);
}

/**
 * xmlSecSignedInfoCalculate:
 *
 *  The way in which the SignedInfo element is presented to the 
 *  canonicalization method is dependent on that method. The following 
 *  applies to algorithms which process XML as nodes or characters:
 *
 *  - XML based canonicalization implementations MUST be provided with 
 *  a [XPath] node-set originally formed from the document containing 
 *  the SignedInfo and currently indicating the SignedInfo, its descendants,
 *  and the attribute and namespace nodes of SignedInfo and its descendant 
 *  elements.
 *
 *  - Text based canonicalization algorithms (such as CRLF and charset 
 *  normalization) should be provided with the UTF-8 octets that represent 
 *  the well-formed SignedInfo element, from the first character to the 
 *  last character of the XML representation, inclusive. This includes 
 *  the entire text of the start and end tags of the SignedInfo element 
 *  as well as all descendant markup and character data (i.e., the text) 
 *  between those tags. Use of text based canonicalization of SignedInfo 
 *  is NOT RECOMMENDED.   	     
 *
 *  =================================
 *  we do not support any non XML based C14N 
 */
static int
xmlSecSignedInfoCalculate(xmlNodePtr signedInfoNode, int sign, 
		xmlSecTransformPtr c14nMethod, xmlSecTransformPtr signMethod, 
		xmlNodePtr signatureValueNode, xmlSecDSigResultPtr result) {
    xmlSecTransformCtx transformCtx; /* todo */
    xmlSecNodeSetPtr nodeSet = NULL;
    xmlSecTransformStatePtr state = NULL;
    xmlSecTransformPtr memBuffer = NULL;
    int res = -1;
    int ret;
    
    xmlSecAssert2(result != NULL, -1);
    xmlSecAssert2(result->ctx != NULL, -1);
    xmlSecAssert2(signedInfoNode != NULL, -1);
    xmlSecAssert2(c14nMethod != NULL, -1);
    xmlSecAssert2(signMethod != NULL, -1);
    xmlSecAssert2(signatureValueNode != NULL, -1);
    
    /* this should be done in different way if C14N is binary! */
    nodeSet = xmlSecNodeSetGetChildren(signedInfoNode->doc, 
					signedInfoNode, 1, 0);
    if(nodeSet == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecNodeSetGetChildren");
	goto done;
    }

    state = xmlSecTransformStateCreate(signedInfoNode->doc, nodeSet, NULL);
    if(state == NULL){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformStateCreate");
	goto done;
    }	

    ret = xmlSecTransformStateUpdate(state, c14nMethod);
    if(ret < 0){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformStateUpdate");
	goto done;
    }

    /* 
     * if requested then insert a memory buffer to capture the digest data 
     */
    if(result->ctx->storeSignatures || result->ctx->fakeSignatures) {
	memBuffer = xmlSecTransformCreate(xmlSecMemBuf, 1);
	if(memBuffer == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformCreate(xmlSecMemBuf)");
	    goto done;
	}
	ret = xmlSecTransformStateUpdate(state, memBuffer);
	if(ret < 0){
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformStateUpdate - %d", ret);
	    goto done;
	}
    }
     
    if(!(result->ctx->fakeSignatures)) {
	ret = xmlSecTransformStateUpdate(state, signMethod);
	if(ret < 0){
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformStateUpdate - %d", ret);
	    goto done;
	}
	signMethod->encode = sign;

	if(sign) {
	    ret = xmlSecTransformStateFinalToNode(state, signatureValueNode, 1, 
						&transformCtx);
	    if(ret < 0) {    
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecTransformStateFinalToNode");
	        goto done;
	    }
        } else {
    	    ret = xmlSecTransformStateFinalVerifyNode(state, signMethod, 
						signatureValueNode, &transformCtx);
	    if(ret < 0) {    
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecTransformStateFinalVerifyNode");
		goto done;
	    }
	}	
	result->result = signMethod->status;
    } else {
	result->result = xmlSecTransformStatusOk; /* in "fake" mode we always ok */
    }

    if(memBuffer != NULL) {
	result->buffer = xmlSecMemBufTransformGetBuffer(memBuffer, 1);
    }
    
    res = 0;
done:    
    if(state != NULL) {
	xmlSecTransformStateDestroy(state);
    }
    if(nodeSet != NULL) {
	xmlSecNodeSetDestroy(nodeSet);
    }
    if(memBuffer != NULL) {
	xmlSecTransformDestroy(memBuffer, 1);
    }
    return(res);
}



/** 
 * xmlSecSignedInfoRead:
 *
 * The SignedInfo  Element (http://www.w3.org/TR/xmldsig-core/#sec-SignedInfo)
 * 
 * The structure of SignedInfo includes the canonicalization algorithm, 
 * a result algorithm, and one or more references. The SignedInfo element 
 * may contain an optional ID attribute that will allow it to be referenced by 
 * other signatures and objects.
 *
 * SignedInfo does not include explicit result or digest properties (such as
 * calculation time, cryptographic device serial number, etc.). If an 
 * application needs to associate properties with the result or digest, 
 * it may include such information in a SignatureProperties element within 
 * an Object element.
 *
 * Schema Definition:
 *
 *  <element name="SignedInfo" type="ds:SignedInfoType"/> 
 *  <complexType name="SignedInfoType">
 *    <sequence> 
 *      <element ref="ds:CanonicalizationMethod"/>
 *      <element ref="ds:SignatureMethod"/> 
 *      <element ref="ds:Reference" maxOccurs="unbounded"/> 
 *    </sequence> 
 *    <attribute name="Id" type="ID" use="optional"/> 
 *  </complexType>
 *    
 * DTD:
 *    
 *  <!ELEMENT SignedInfo (CanonicalizationMethod, SignatureMethod,  Reference+) >
 *  <!ATTLIST SignedInfo  Id   ID      #IMPLIED>
 * 
 */
static int
xmlSecSignedInfoRead(xmlNodePtr signedInfoNode,  int sign,
	   	      xmlNodePtr signatureValueNode, xmlNodePtr keyInfoNode,
		      xmlSecDSigResultPtr result) {
    xmlSecTransformPtr c14nMethod = NULL;
    xmlSecTransformPtr signMethod = NULL;
    xmlNodePtr cur;
    xmlSecReferenceResultPtr ref;
    int ret;
    int res = -1;

    xmlSecAssert2(result != NULL, -1);
    xmlSecAssert2(result->ctx != NULL, -1);
    xmlSecAssert2(signedInfoNode != NULL, -1);
    xmlSecAssert2(signatureValueNode != NULL, -1);
    
    cur = xmlSecGetNextElementNode(signedInfoNode->children);
    
    /* first node is required CanonicalizationMethod */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "CanonicalizationMethod", xmlSecDSigNs))) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "CanonicalizationMethod");
	goto done;
    }
    c14nMethod = xmlSecTransformNodeRead(cur, xmlSecTransformUsageC14NMethod, 1);
    if(c14nMethod == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformNodeRead(c14nNode)");
	goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next node is required SignatureMethod */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "SignatureMethod", xmlSecDSigNs))) {
    	xmlSecError(XMLSEC_ERRORS_HERE,	
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "SignatureMethod");
	goto done;
    }
    signMethod = xmlSecTransformNodeRead(cur, xmlSecTransformUsageSignatureMethod, 1);
    if(signMethod == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformNodeRead(SignatureMethod Node)");
	goto done;
    }
    result->signMethod = signMethod->id;
    cur = xmlSecGetNextElementNode(cur->next);

    /* now we are ready to get key, KeyInfo node may be NULL! */
    if((result->key == NULL) && (xmlSecDSigResultGetKeyCallback(result) != NULL)) {
	xmlSecKeyInfoCtxPtr keyInfoCtx;

	keyInfoCtx = &(result->ctx->keyInfoCtx);	
	ret = xmlSecTransformSetKeyReq(signMethod, keyInfoCtx);
	if(ret < 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformSetKeyReq");
	    goto done;
	}		
	result->key = (xmlSecDSigResultGetKeyCallback(result))(keyInfoNode, keyInfoCtx);
    }    
    if(result->key == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_KEY_NOT_FOUND,
		    " ");
	goto done;
    }
    ret = xmlSecTransformSetKey(signMethod, result->key);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformAddKey - %d", ret);
	goto done;
    }
    if(sign && (keyInfoNode != NULL)) {
	/* update KeyInfo! */
	/* todo: do we want to write anything else??? */
	result->ctx->keyInfoCtx.keyType = xmlSecKeyDataTypePublic;
	ret = xmlSecKeyInfoNodeWrite(keyInfoNode, 
		    		     result->key, 
				     &result->ctx->keyInfoCtx);
	if(ret < 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyInfoNodeWrite - %d", ret);
	    goto done;
	}	
    }
    
    /* next is Reference nodes (at least one must present!) */
    while((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "Reference", xmlSecDSigNs)) {
	ref = xmlSecReferenceCreate(xmlSecSignedInfoReference, 
				     result->ctx, cur);
	if(ref == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecReferenceCreate");
	    goto done;
	}
	
	ret = xmlSecReferenceRead(ref, cur, sign);
	if(ret < 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecReferenceRead - %d", ret);
	    xmlSecReferenceDestroy(ref);
	    goto done;
	}
	
	if(xmlSecDSigResultAddSignedInfoRef(result, ref) == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecDSigResultAddSignedInfoRef");
	    xmlSecReferenceDestroy(ref);
	    goto done;
	}	


	if((!sign) && (ref->result != xmlSecTransformStatusOk)) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_DSIG_INVALID_REFERENCE,
			" ");
	    /* "soft" error */
	    res = 0;
	    goto done;
	}
	cur = xmlSecGetNextElementNode(cur->next); 
    }
    
    if(result->firstSignRef == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "Reference");
	goto done;
    }

    if(cur != NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    (cur->name != NULL) ? (char*)cur->name : "NULL");
	goto done;
    }

    /* calculate result and write/verify it*/
    ret = xmlSecSignedInfoCalculate(signedInfoNode, sign,
				    c14nMethod, signMethod, 
				    signatureValueNode, result);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecSignedInfoCalculate - %d", ret);
	goto done;
    }				    
    
    /* we are ok! */
    res = 0;    
done:
    if(c14nMethod != NULL) {
	xmlSecTransformDestroy(c14nMethod, 1);
    }
    if(signMethod != NULL) {
	xmlSecTransformDestroy(signMethod, 1);
    }
    return(res);
}


/**
 * xmlSecReferenceRead:
 *
 * The Reference  Element (http://www.w3.org/TR/xmldsig-core/#sec-Reference)
 * 
 * Reference is an element that may occur one or more times. It specifies 
 * a digest algorithm and digest value, and optionally an identifier of the 
 * object being signed, the type of the object, and/or a list of transforms 
 * to be applied prior to digesting. The identification (URI) and transforms 
 * describe how the digested content (i.e., the input to the digest method) 
 * was created. The Type attribute facilitates the processing of referenced 
 * data. For example, while this specification makes no requirements over 
 * external data, an application may wish to signal that the referent is a 
 * Manifest. An optional ID attribute permits a Reference to be referenced 
 * from elsewhere.
 *
 * Schema Definition:
 *
 *  <element name="Reference" type="ds:ReferenceType"/>
 *  <complexType name="ReferenceType">
 *    <sequence> 
 *      <element ref="ds:Transforms" minOccurs="0"/> 
 *      <element ref="ds:DigestMethod"/> 
 *      <element ref="ds:DigestValue"/> 
 *    </sequence>
 *    <attribute name="Id" type="ID" use="optional"/> 
 *    <attribute name="URI" type="anyURI" use="optional"/> 
 *    <attribute name="Type" type="anyURI" use="optional"/> 
 *  </complexType>
 *    
 * DTD:
 *    
 *   <!ELEMENT Reference (Transforms?, DigestMethod, DigestValue)  >
 *   <!ATTLIST Reference Id  ID  #IMPLIED
 *   		URI CDATA   #IMPLIED
 * 		Type    CDATA   #IMPLIED>
 *
 *
 */
static int
xmlSecReferenceRead(xmlSecReferenceResultPtr ref, xmlNodePtr self, int sign) {
    xmlSecTransformCtx transformCtx; /* todo */
    xmlNodePtr cur;
    xmlSecTransformStatePtr state = NULL;
    xmlSecTransformPtr digestMethod = NULL;
    xmlNodePtr digestValueNode;
    xmlSecTransformPtr memBuffer = NULL;
    int res = -1;
    int ret;
 
    xmlSecAssert2(ref != NULL, -1);
    xmlSecAssert2(self != NULL, -1);

    cur = xmlSecGetNextElementNode(self->children);
    
    /* read attributes first */
    ref->uri = xmlGetProp(self, BAD_CAST "URI");
    ref->id  = xmlGetProp(self, BAD_CAST "Id");
    ref->type= xmlGetProp(self, BAD_CAST "Type");

    state = xmlSecTransformStateCreate(self->doc, NULL, (char*)ref->uri);
    if(state == NULL){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformStateCreate");
	goto done;
    }	

    /* first is optional Transforms node */
    if((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "Transforms", xmlSecDSigNs)) {
	ret = xmlSecTransformsNodeRead(state, cur);
	if(ret < 0){
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformsNodeRead - %d", ret);
	    goto done;
	}	
	cur = xmlSecGetNextElementNode(cur->next);
    }

    /* 
     * if requested then insert a memory buffer to capture the digest data 
     */
    if(ref->ctx->storeReferences) {
	memBuffer = xmlSecTransformCreate(xmlSecMemBuf, 1);
	if(memBuffer == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformCreate(xmlSecMemBuf)");
	    goto done;
	}
	ret = xmlSecTransformStateUpdate(state, memBuffer);
	if(ret < 0){
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformStateUpdate - %d", ret);
	    goto done;
	}
    }
     
    /* next node is required DigestMethod */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "DigestMethod", xmlSecDSigNs))) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "DigestMethod");
	goto done;
    }
    digestMethod = xmlSecTransformNodeRead(cur, xmlSecTransformUsageDigestMethod, 1);
    if(digestMethod == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformNodeRead(digestMethodNode)");
	goto done;
    }
    digestMethod->encode = sign;
    
    ret = xmlSecTransformStateUpdate(state, digestMethod);
    if(ret < 0){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformStateUpdate(digestMethod)");
	goto done;
    }
    ref->digestMethod = digestMethod->id;
    cur = xmlSecGetNextElementNode(cur->next);

    /* next node is required DigestValue */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "DigestValue", xmlSecDSigNs))) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "DigestValue");
	goto done;
    }
    digestValueNode = cur;
    cur = xmlSecGetNextElementNode(cur->next);     

    if(cur != NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    (cur->name != NULL) ? (char*)cur->name : "NULL");
	goto done;
    }
    
    if(sign) {
	ret = xmlSecTransformStateFinalToNode(state, digestValueNode, 1, &transformCtx);
	if(ret < 0) {    
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformStateFinalToNode");
	    goto done;
	}
    } else {
	ret = xmlSecTransformStateFinalVerifyNode(state, digestMethod, digestValueNode, &transformCtx);
	if(ret < 0) {    
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformStateFinalVerifyNode");
	    goto done;
	}
    }	
    ref->result = digestMethod->status;
    
    if(memBuffer != NULL) {
	ref->buffer = xmlSecMemBufTransformGetBuffer(memBuffer, 1);
    }
    res = 0;

done:
    if(state != NULL) {
	xmlSecTransformStateDestroy(state);
    }
    if(digestMethod != NULL) {
	xmlSecTransformDestroy(digestMethod, 1);
    }
    if(memBuffer != NULL) {
	xmlSecTransformDestroy(memBuffer, 1);
    }
    return(res);
}

    


/**
 * xmlSecReferenceCreate:
 *
 */
static xmlSecReferenceResultPtr	
xmlSecReferenceCreate(xmlSecReferenceType type, xmlSecDSigCtxPtr ctx, xmlNodePtr self) {
    xmlSecReferenceResultPtr ref;
        
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(self != NULL, NULL);

    /*
     * Allocate a new xmlSecReference and fill the fields.
     */
    ref = (xmlSecReferenceResultPtr) xmlMalloc(sizeof(xmlSecReferenceResult));
    if(ref == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecReferenceResult)=%d",
		    sizeof(xmlSecReferenceResult));
	return(NULL);
    }
    memset(ref, 0, sizeof(xmlSecReferenceResult));
    
    ref->refType = type;
    ref->ctx = ctx;
    ref->self = self;    
    return(ref);
}

/**
 * xmlSecReferenceDestroy:
 */
static void			
xmlSecReferenceDestroy(xmlSecReferenceResultPtr ref) {
    xmlSecAssert(ref != NULL);
    
    /* destroy all strings */
    if(ref->uri) {
	xmlFree(ref->uri);
    }
    if(ref->id) {
	xmlFree(ref->id);
    }
    if(ref->type) {
	xmlFree(ref->type);
    }
    
    /* destroy buffer */
    if(ref->buffer != NULL) {
	xmlSecBufferDestroy(ref->buffer); 
    }
    
    /* remove from the chain */
    if(ref->next != NULL) {
	ref->next->prev = ref->prev;
    }
    if(ref->prev != NULL) {
	ref->prev->next = ref->next;
    }
    memset(ref, 0, sizeof(xmlSecReferenceResult));
    xmlFree(ref);
}

/**
 * xmlSecReferenceDestroyAll:
 */
static void
xmlSecReferenceDestroyAll(xmlSecReferenceResultPtr ref) {
    xmlSecAssert(ref != NULL);

    while(ref->next != NULL) {
	xmlSecReferenceDestroy(ref->next);
    }    
    while(ref->prev != NULL) {
	xmlSecReferenceDestroy(ref->prev);
    }    
    xmlSecReferenceDestroy(ref);
}

/**
 * xmlSecDSiggReferenceDebugDump:
 */
static void
xmlSecDSigReferenceDebugDump(xmlSecReferenceResultPtr ref, FILE *output) {
    xmlSecAssert(ref != NULL);
    xmlSecAssert(output != NULL);

    fprintf(output, "=== REFERENCE \n");
    fprintf(output, "==== ref type: %s\n", 
	    (ref->refType == xmlSecSignedInfoReference) ? 
		"SignedInfo Reference" : "Manifest Reference"); 
    fprintf(output, "==== result: %s\n", 
	    (ref->result == xmlSecTransformStatusOk) ? "OK" : "FAIL");
    fprintf(output, "==== digest method: %s\n", 
	    (ref->digestMethod != NULL) ? (char*)ref->digestMethod->href : "NULL"); 
    fprintf(output, "==== uri: %s\n", 
	    (ref->uri != NULL) ? (char*)ref->uri : "NULL"); 
    fprintf(output, "==== type: %s\n", 
	    (ref->type != NULL) ? (char*)ref->type : "NULL"); 
    fprintf(output, "==== id: %s\n", 
	    (ref->id != NULL) ? (char*)ref->id : "NULL"); 
    
    if(ref->buffer != NULL) {
	fprintf(output, "==== start buffer:\n");
	fwrite(xmlSecBufferGetData(ref->buffer), 
	       xmlSecBufferGetSize(ref->buffer), 1,
	       output);
	fprintf(output, "\n==== end buffer:\n");
    }   	    
}

/**
 * xmlSecDSigReferenceDebugDumpAll:
 */
static void
xmlSecDSigReferenceDebugDumpAll(xmlSecReferenceResultPtr ref, FILE *output) {
    xmlSecReferenceResultPtr ptr;

    xmlSecAssert(ref != NULL);
    xmlSecAssert(output != NULL);
    
    ptr = ref->prev;
    while(ptr != NULL) {
	xmlSecDSigReferenceDebugDump(ptr, output);
	ptr = ptr->prev;
    }
    xmlSecDSigReferenceDebugDump(ref, output);
    ptr = ref->next;
    while(ptr != NULL) {
	xmlSecDSigReferenceDebugDump(ptr, output);
	ptr = ptr->next;
    }
}

/**
 * xmlSecDSiggReferenceDebugXmlDump:
 */
static void
xmlSecDSigReferenceDebugXmlDump(xmlSecReferenceResultPtr ref, FILE *output) {
    xmlSecAssert(ref != NULL);
    xmlSecAssert(output != NULL);

    fprintf(output, "<Reference origin=\"%s\">\n",
	    (ref->refType == xmlSecSignedInfoReference) ? 
	    "SignedInfo" : "Manifest"); 
    fprintf(output, "<Status>%s</Status>\n", 
	    (ref->result == xmlSecTransformStatusOk) ? "OK" : "FAIL");
    fprintf(output, "<DigestMethod>%s</DigestMethod>\n", 
	    (ref->digestMethod != NULL) ? (char*)ref->digestMethod->href : "NULL"); 
    if(ref->uri != NULL) {
	fprintf(output, "<URI>%s</URI>\n", ref->uri);
    }
    if(ref->type != NULL) {
        fprintf(output, "<Type>%s</Type>\n", ref->type);
    }
    if(ref->id != NULL) {
	fprintf(output, "<Id>%s</Id>\n", ref->id); 
    }
    if(ref->buffer != NULL) {
	fprintf(output, "<DigestBuffer>");
	fwrite(xmlSecBufferGetData(ref->buffer), 
	       xmlSecBufferGetSize(ref->buffer), 1,
	       output);
	fprintf(output, "</DigestBuffer>\n");
    }   	    
    fprintf(output, "</Reference>\n");
}

/**
 * xmlSecDSigReferenceDebugXmlDumpAll:
 */
static void
xmlSecDSigReferenceDebugXmlDumpAll(xmlSecReferenceResultPtr ref, FILE *output) {
    xmlSecReferenceResultPtr ptr;

    xmlSecAssert(ref != NULL);
    xmlSecAssert(output != NULL);
    
    ptr = ref->prev;
    while(ptr != NULL) {
	xmlSecDSigReferenceDebugXmlDump(ptr, output);
	ptr = ptr->prev;
    }
    xmlSecDSigReferenceDebugXmlDump(ref, output);
    ptr = ref->next;
    while(ptr != NULL) {
	xmlSecDSigReferenceDebugXmlDump(ptr, output);
	ptr = ptr->next;
    }
}

/**
 * xmlSecObjectRead:
 * 
 * The Object Element (http://www.w3.org/TR/xmldsig-core/#sec-Object)
 * 
 * Object is an optional element that may occur one or more times. When 
 * present, this element may contain any data. The Object element may include 
 * optional MIME type, ID, and encoding attributes.
 *     
 * Schema Definition:
 *     
 * <element name="Object" type="ds:ObjectType"/> 
 * <complexType name="ObjectType" mixed="true">
 *   <sequence minOccurs="0" maxOccurs="unbounded">
 *     <any namespace="##any" processContents="lax"/>
 *   </sequence>
 *   <attribute name="Id" type="ID" use="optional"/> 
 *   <attribute name="MimeType" type="string" use="optional"/>
 *   <attribute name="Encoding" type="anyURI" use="optional"/> 
 * </complexType>
 *	
 * DTD:
 *	
 * <!ELEMENT Object (#PCDATA|Signature|SignatureProperties|Manifest %Object.ANY;)* >
 * <!ATTLIST Object  Id  ID  #IMPLIED 
 *                   MimeType    CDATA   #IMPLIED 
 *                   Encoding    CDATA   #IMPLIED >
 */
static int
xmlSecObjectRead(xmlNodePtr objectNode, int sign, xmlSecDSigResultPtr result) {
    xmlNodePtr cur;
    int ret;
    
    xmlSecAssert2(result != NULL, -1);
    xmlSecAssert2(result->ctx != NULL, -1);
    xmlSecAssert2(objectNode != NULL, -1);
    
    cur = xmlSecGetNextElementNode(objectNode->children);
    while(cur != NULL) {
	if(xmlSecCheckNodeName(cur, BAD_CAST "Manifest", xmlSecDSigNs)) {
	    ret = xmlSecManifestRead(cur, sign, result);
	    if(ret < 0){
    		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecManifestRead - %d", ret);
		return(-1);	    
	    }
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    return(0);
}

/**
 * xmlSecManifestRead: 
 *
 * The Manifest  Element (http://www.w3.org/TR/xmldsig-core/#sec-Manifest)
 *
 * The Manifest element provides a list of References. The difference from 
 * the list in SignedInfo is that it is application defined which, if any, of 
 * the digests are actually checked against the objects referenced and what to 
 * do if the object is inaccessible or the digest compare fails. If a Manifest 
 * is pointed to from SignedInfo, the digest over the Manifest itself will be 
 * checked by the core result validation behavior. The digests within such 
 * a Manifest are checked at the application's discretion. If a Manifest is 
 * referenced from another Manifest, even the overall digest of this two level 
 * deep Manifest might not be checked.
 *     
 * Schema Definition:
 *     
 * <element name="Manifest" type="ds:ManifestType"/> 
 * <complexType name="ManifestType">
 *   <sequence>
 *     <element ref="ds:Reference" maxOccurs="unbounded"/> 
 *   </sequence> 
 *   <attribute name="Id" type="ID" use="optional"/> 
 *  </complexType>
 *	
 * DTD:
 *
 * <!ELEMENT Manifest (Reference+)  >
 * <!ATTLIST Manifest Id ID  #IMPLIED >
 */
static int
xmlSecManifestRead(xmlNodePtr manifestNode, int sign, xmlSecDSigResultPtr result) {
    xmlNodePtr cur;
    xmlSecReferenceResultPtr ref;
    int ret;
    
    xmlSecAssert2(result != NULL, -1);
    xmlSecAssert2(result->ctx != NULL, -1);
    xmlSecAssert2(manifestNode != NULL, -1);

    cur = xmlSecGetNextElementNode(manifestNode->children);
    while((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "Reference", xmlSecDSigNs)) { 
	ref = xmlSecReferenceCreate(xmlSecManifestReference, 
				     result->ctx, cur);
	if(ref == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecReferenceCreate");
	    return(-1);
	}
	
	ret = xmlSecReferenceRead(ref, cur, sign);
	if(ret < 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecReferenceRead - %d", ret);
	    xmlSecReferenceDestroy(ref);
	    return(-1);
	}
	
	if(xmlSecDSigResultAddManifestRef(result, ref) == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecDSigResultAddManifestRef");
	    xmlSecReferenceDestroy(ref);
	    return(-1);
	}	
	cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    (cur->name != NULL) ? (char*)cur->name : "NULL");
	return(-1);
    }    
    return(0);
}

#endif /* XMLSEC_NO_XMLDSIG */


