/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * "XML Digital Signature" implementation
 *  http://www.w3.org/TR/xmldsig-core/
 *  http://www.w3.org/Signature/Overview.html
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_XMLDSIG

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
#include <xmlsec/membuf.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/errors.h>

/**************************************************************************
 *
 * xmlSecDSigCtx
 *
 *************************************************************************/
static int	xmlSecDSigCtxProcessSignatureNode	(xmlSecDSigCtxPtr dsigCtx, 
							 xmlNodePtr node);
static int	xmlSecDSigCtxProcessSignedInfoNode	(xmlSecDSigCtxPtr dsigCtx, 
							 xmlNodePtr node);
static int	xmlSecDSigCtxProcessKeyInfoNode		(xmlSecDSigCtxPtr dsigCtx, 
							 xmlNodePtr node);
static int	xmlSecDSigCtxProcessObjectNode		(xmlSecDSigCtxPtr dsigCtx, 
							 xmlNodePtr node);
static int	xmlSecDSigCtxProcessManifestNode	(xmlSecDSigCtxPtr dsigCtx, 
							 xmlNodePtr node);

/* The ID attribute in XMLDSig is 'Id' */
static const xmlChar*		xmlSecDSigIds[] = { xmlSecAttrId, NULL };

/**
 * xmlSecDSigCtxCreate:
 * @keysMngr: 		the pointer to keys manager.
 *
 * Creates <dsig:Signature/> element processing context.
 * The caller is responsible for destroying returend object by calling 
 * #xmlSecDSigCtxDestroy function.
 *
 * Returns pointer to newly allocated context object or NULL if an error
 * occurs.
 */
xmlSecDSigCtxPtr	
xmlSecDSigCtxCreate(xmlSecKeysMngrPtr keysMngr) {
    xmlSecDSigCtxPtr dsigCtx;
    int ret;
    
    dsigCtx = (xmlSecDSigCtxPtr) xmlMalloc(sizeof(xmlSecDSigCtx));
    if(dsigCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecDSigCtx)=%d", 
		    sizeof(xmlSecDSigCtx));
	return(NULL);
    }
    
    ret = xmlSecDSigCtxInitialize(dsigCtx, keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecDSigCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecDSigCtxDestroy(dsigCtx);
	return(NULL);   
    }
    return(dsigCtx);    
}

/**
 * xmlSecDSigCtxDestroy:
 * @dsigCtx:		the pointer to <dsig:Signature/> processing context.
 *
 * Destroy context object created with #xmlSecDSigCtxCreate function.
 */
void  
xmlSecDSigCtxDestroy(xmlSecDSigCtxPtr dsigCtx) {
    xmlSecAssert(dsigCtx != NULL);
    
    xmlSecDSigCtxFinalize(dsigCtx);
    xmlFree(dsigCtx);
}

/**
 * xmlSecDSigCtxInitialize:
 * @dsigCtx:		the pointer to <dsig:Signature/> processing context.
 * @keysMngr: 		the pointer to keys manager.
 *
 * Initializes <dsig:Signature/> element processing context.
 * The caller is responsible for cleaing up returend object by calling 
 * #xmlSecDSigCtxFinalize function.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecDSigCtxInitialize(xmlSecDSigCtxPtr dsigCtx, xmlSecKeysMngrPtr keysMngr) {
    int ret;
    
    xmlSecAssert2(dsigCtx != NULL, -1);
    
    memset(dsigCtx, 0, sizeof(xmlSecDSigCtx));

    /* initialize key info */
    ret = xmlSecKeyInfoCtxInitialize(&(dsigCtx->keyInfoReadCtx), keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyInfoCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }
    dsigCtx->keyInfoReadCtx.mode = xmlSecKeyInfoModeRead;
    
    ret = xmlSecKeyInfoCtxInitialize(&(dsigCtx->keyInfoWriteCtx), keysMngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyInfoCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }
    dsigCtx->keyInfoWriteCtx.mode = xmlSecKeyInfoModeWrite;
    /* it's not wise to write private key :) */
    dsigCtx->keyInfoWriteCtx.keyReq.keyType = xmlSecKeyDataTypePublic;

    /* initializes transforms dsigCtx */
    ret = xmlSecTransformCtxInitialize(&(dsigCtx->transformCtx));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }

    /* references lists from SignedInfo and Manifest elements */
    xmlSecPtrListInitialize(&(dsigCtx->signedInfoReferences), 
			    xmlSecDSigReferenceCtxListId);
    xmlSecPtrListInitialize(&(dsigCtx->manifestReferences), 
			    xmlSecDSigReferenceCtxListId);    

    dsigCtx->enabledReferenceUris = xmlSecTransformUriTypeAny;
    return(0);
}

/**
 * xmlSecDSigCtxFinalize:
 * @dsigCtx:		the pointer to <dsig:Signature/> processing context.
 *
 * Cleans up @dsigCtx object initialized with #xmlSecDSigCtxInitialize function.
 */
void 
xmlSecDSigCtxFinalize(xmlSecDSigCtxPtr dsigCtx) {
    xmlSecAssert(dsigCtx != NULL);

    xmlSecTransformCtxFinalize(&(dsigCtx->transformCtx));
    xmlSecKeyInfoCtxFinalize(&(dsigCtx->keyInfoReadCtx));
    xmlSecKeyInfoCtxFinalize(&(dsigCtx->keyInfoWriteCtx));
    xmlSecPtrListFinalize(&(dsigCtx->signedInfoReferences));
    xmlSecPtrListFinalize(&(dsigCtx->manifestReferences));

    if(dsigCtx->enabledReferenceTransforms != NULL) {
	xmlSecPtrListDestroy(dsigCtx->enabledReferenceTransforms);	
    }
    if(dsigCtx->signKey != NULL) {
	xmlSecKeyDestroy(dsigCtx->signKey);
    }
    if(dsigCtx->id != NULL) {
	xmlFree(dsigCtx->id);
    }	
    memset(dsigCtx, 0, sizeof(xmlSecDSigCtx));
}

/**
 * xmlSecDSigCtxEnableReferenceTransform:
 * @dsigCtx:		the pointer to <dsig:Signature/> processing context.
 * @transformId:	the transform klass.
 *
 * Enables @transformId for <dsig:Reference/> elements processing.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecDSigCtxEnableReferenceTransform(xmlSecDSigCtxPtr dsigCtx, xmlSecTransformId transformId) {
    int ret;
    
    xmlSecAssert2(dsigCtx != NULL, -1);
    xmlSecAssert2(dsigCtx->result == NULL, -1);
    xmlSecAssert2(transformId != xmlSecTransformIdUnknown, -1);

    if(dsigCtx->enabledReferenceTransforms == NULL) {
	dsigCtx->enabledReferenceTransforms = xmlSecPtrListCreate(xmlSecTransformIdListId);
	if(dsigCtx->enabledReferenceTransforms == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecPtrListCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);   
	}
    }	
	
    ret = xmlSecPtrListAdd(dsigCtx->enabledReferenceTransforms, (void*)transformId);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecPtrListAdd",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }
    return(0);
}

/**
 * xmlSecDSigCtxEnableSignatureTransform:
 * @dsigCtx:		the pointer to <dsig:Signature/> processing context.
 * @transformId:	the transform klass.
 *
 * Enables @transformId for <dsig:SignedInfo/> element processing.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecDSigCtxEnableSignatureTransform(xmlSecDSigCtxPtr dsigCtx, xmlSecTransformId transformId) {
    xmlSecAssert2(dsigCtx != NULL, -1);
    xmlSecAssert2(dsigCtx->result == NULL, -1);
    xmlSecAssert2(transformId != xmlSecTransformIdUnknown, -1);

    return(xmlSecPtrListAdd(&(dsigCtx->transformCtx.enabledTransforms), (void*)transformId));
}

/**
 * xmlSecDSigCtxGetPreSignBuffer:
 * @dsigCtx:		the pointer to <dsig:Signature/> processing context.
 * 
 * Gets pointer to the buffer with serialized <dsig:SignedInfo/> element
 * just before signature claculation (valid if and only if 
 * #XMLSEC_DSIG_FLAGS_STORE_SIGNATURE context flag is set.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
xmlSecBufferPtr 
xmlSecDSigCtxGetPreSignBuffer(xmlSecDSigCtxPtr dsigCtx) {
    xmlSecAssert2(dsigCtx != NULL, NULL);
    
    return((dsigCtx->preSignMemBufMethod != NULL) ? 
	    xmlSecTransformMemBufGetBuffer(dsigCtx->preSignMemBufMethod) : NULL);
}

/**
 * xmlSecDSigCtxSign:
 * @dsigCtx:		the pointer to <dsig:Signature/> processing context.
 * @tmpl:		the pointer to <dsig:Signature/> node with signature template.
 *
 * Signs the data as described in @tmpl node.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecDSigCtxSign(xmlSecDSigCtxPtr dsigCtx, xmlNodePtr tmpl) {
    int ret;
    
    xmlSecAssert2(dsigCtx != NULL, -1);
    xmlSecAssert2(dsigCtx->result == NULL, -1);
    xmlSecAssert2(tmpl != NULL, -1);
    xmlSecAssert2(tmpl->doc != NULL, -1);

    /* add ids for Signature nodes */
    dsigCtx->operation 	= xmlSecTransformOperationSign;
    dsigCtx->status 	= xmlSecDSigStatusUnknown;
    xmlSecAddIDs(tmpl->doc, tmpl, xmlSecDSigIds);

    /* read signature template */
    ret = xmlSecDSigCtxProcessSignatureNode(dsigCtx, tmpl);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecDSigCtxSigantureProcessNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    xmlSecAssert2(dsigCtx->signMethod != NULL, -1);
    xmlSecAssert2(dsigCtx->signValueNode != NULL, -1);

    /* references processing might change the status */
    if(dsigCtx->status != xmlSecDSigStatusUnknown) {
	return(0);
    }

    /* check what we've got */
    dsigCtx->result = dsigCtx->transformCtx.result;
    if((dsigCtx->result == NULL) || (xmlSecBufferGetData(dsigCtx->result) == NULL)) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_RESULT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* write signed data to xml */
    xmlNodeSetContentLen(dsigCtx->signValueNode,
			    xmlSecBufferGetData(dsigCtx->result),
			    xmlSecBufferGetSize(dsigCtx->result));
    
    /* set success status and we are done */
    dsigCtx->status = xmlSecDSigStatusSucceeded;
    return(0);    
}

/**
 * xmlSecDSigCtxVerify:
 * @dsigCtx:		the pointer to <dsig:Signature/> processing context.
 * @node:		the pointer with <dsig:Signature/> node.
 * 
 * Vaidates signature in the @node. The verification result is returned
 * in #status member of the @dsigCtx object.
 *
 * Returns 0 on success (check #status member of @dsigCtx to get 
 * signature verification result) or a negative value if an error occurs.
 */
int 
xmlSecDSigCtxVerify(xmlSecDSigCtxPtr dsigCtx, xmlNodePtr node) {
    int ret;
    
    xmlSecAssert2(dsigCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(node->doc != NULL, -1);

    /* add ids for Signature nodes */
    dsigCtx->operation 	= xmlSecTransformOperationVerify;
    dsigCtx->status 	= xmlSecDSigStatusUnknown;
    xmlSecAddIDs(node->doc, node, xmlSecDSigIds);
    
    /* read siganture info */
    ret = xmlSecDSigCtxProcessSignatureNode(dsigCtx, node);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecDSigCtxSigantureProcessNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    xmlSecAssert2(dsigCtx->signMethod != NULL, -1);
    xmlSecAssert2(dsigCtx->signValueNode != NULL, -1);

    /* references processing might change the status */
    if(dsigCtx->status != xmlSecDSigStatusUnknown) {
	return(0);
    }

    /* verify SignatureValue node content */
    ret = xmlSecTransformVerifyNodeContent(dsigCtx->signMethod, dsigCtx->signValueNode,
					   &(dsigCtx->transformCtx));
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformVerifyNodeContent",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    /* set status and we are done */
    if(dsigCtx->signMethod->status == xmlSecTransformStatusOk) {
        dsigCtx->status = xmlSecDSigStatusSucceeded;
    } else {
        dsigCtx->status = xmlSecDSigStatusInvalid;
    }
    return(0);
}

/**
 * xmlSecDSigCtxProcessSignatureNode:
 *
 * The Signature  element (http://www.w3.org/TR/xmldsig-core/#sec-Signature)
 *
 * The Signature element is the root element of an XML Signature. 
 * Implementation MUST generate laxly schema valid [XML-schema] Signature 
 * elements as specified by the following schema:
 * The way in which the SignedInfo element is presented to the 
 * canonicalization method is dependent on that method. The following 
 * applies to algorithms which process XML as nodes or characters:
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
xmlSecDSigCtxProcessSignatureNode(xmlSecDSigCtxPtr dsigCtx, xmlNodePtr node) {
    xmlSecTransformDataType firstType;
    xmlNodePtr signedInfoNode = NULL;
    xmlNodePtr keyInfoNode = NULL;
    xmlNodePtr cur;
    int ret;
    
    xmlSecAssert2(dsigCtx != NULL, -1);
    xmlSecAssert2((dsigCtx->operation == xmlSecTransformOperationSign) || (dsigCtx->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(dsigCtx->status == xmlSecDSigStatusUnknown, -1);
    xmlSecAssert2(dsigCtx->signValueNode == NULL, -1);
    xmlSecAssert2(dsigCtx->signMethod == NULL, -1);
    xmlSecAssert2(dsigCtx->c14nMethod == NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    if(!xmlSecCheckNodeName(node, xmlSecNodeSignature, xmlSecDSigNs)) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(node)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "expected=%s",
		    xmlSecErrorsSafeString(xmlSecNodeSignature));
	return(-1);	    
    }

    /* read node data */
    xmlSecAssert2(dsigCtx->id == NULL, -1);
    dsigCtx->id = xmlGetProp(node, xmlSecAttrId);

    /* first node is required SignedInfo */
    cur = xmlSecGetNextElementNode(node->children);    
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeSignedInfo, xmlSecDSigNs))) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "expected=%s",
		    xmlSecErrorsSafeString(xmlSecNodeSignedInfo));
        return(-1);
    }
    signedInfoNode = cur;
    cur = xmlSecGetNextElementNode(cur->next);

    /* next node is required SignatureValue */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeSignatureValue, xmlSecDSigNs))) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "expected=%s",
		    xmlSecErrorsSafeString(xmlSecNodeSignatureValue));
	return(-1);
    }
    dsigCtx->signValueNode = cur;
    cur = xmlSecGetNextElementNode(cur->next);

    /* next node is optional KeyInfo */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeKeyInfo, xmlSecDSigNs))) {
	keyInfoNode = cur;
	cur = xmlSecGetNextElementNode(cur->next);
    } else {
	keyInfoNode = NULL;
    }
    
    /* next nodes are optional Object nodes */
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeObject, xmlSecDSigNs))) {
	/* read manifests from objects */
	if((dsigCtx->flags & XMLSEC_DSIG_FLAGS_IGNORE_MANIFESTS) == 0) {
	    ret = xmlSecDSigCtxProcessObjectNode(dsigCtx, cur);
	    if(ret < 0) {
    		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlSecDSigCtxProcessObjectNode",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);	    	    
	    }
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* if there is something left than it's an error */
    if(cur != NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* now validated all the references and prepare transform */
    ret = xmlSecDSigCtxProcessSignedInfoNode(dsigCtx, signedInfoNode);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecDSigCtxProcessSignedInfoNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }				
    /* references processing might change the status */
    if(dsigCtx->status != xmlSecDSigStatusUnknown) {
	return(0);
    }
    
    /* as the result, we should have sign and c14n methods set */    
    xmlSecAssert2(dsigCtx->signMethod != NULL, -1);
    xmlSecAssert2(dsigCtx->c14nMethod != NULL, -1);

    ret = xmlSecDSigCtxProcessKeyInfoNode(dsigCtx, keyInfoNode);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecDSigCtxProcessKeyInfoNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }				
    /* as the result, we should have a key */
    xmlSecAssert2(dsigCtx->signKey != NULL, -1);

    /* if we need to write result to xml node then we need base64 encode result */
    if(dsigCtx->operation == xmlSecTransformOperationSign) {	
	xmlSecTransformPtr base64Encode;
	
	/* we need to add base64 encode transform */
	base64Encode = xmlSecTransformCtxCreateAndAppend(&(dsigCtx->transformCtx), 
							 xmlSecTransformBase64Id);
    	if(base64Encode == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCtxCreateAndAppend",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	base64Encode->operation = xmlSecTransformOperationEncode;
    }

    firstType = xmlSecTransformGetDataType(dsigCtx->transformCtx.first, 
					   xmlSecTransformModePush, 
					   &(dsigCtx->transformCtx));
    if((firstType & xmlSecTransformDataTypeXml) != 0) {
	xmlSecNodeSetPtr nodeset = NULL;

	xmlSecAssert2(signedInfoNode != NULL, -1);
        nodeset = xmlSecNodeSetGetChildren(signedInfoNode->doc, signedInfoNode, 1, 0);
	if(nodeset == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecNodeSetGetChildren",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s",
		        xmlSecErrorsSafeString(xmlSecNodeGetName(signedInfoNode)));
	    return(-1);
	}

	/* calculate the signature */
	ret = xmlSecTransformCtxXmlExecute(&(dsigCtx->transformCtx), nodeset);
	if(ret < 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
		        NULL,
			"xmlSecTransformCtxXmlExecute",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecNodeSetDestroy(nodeset);
	    return(-1);
	}
	xmlSecNodeSetDestroy(nodeset);
    } else {
	/* TODO */
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "the binary c14n transforms are not supported yet",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

/** 
 * xmlSecDSigCtxProcessSignedInfoNode:
 *
 * The SignedInfo Element (http://www.w3.org/TR/xmldsig-core/#sec-SignedInfo)
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
xmlSecDSigCtxProcessSignedInfoNode(xmlSecDSigCtxPtr dsigCtx, xmlNodePtr node) {
    xmlSecDSigReferenceCtxPtr dsigRefCtx;
    xmlNodePtr cur;
    int ret;
    
    xmlSecAssert2(dsigCtx != NULL, -1);	
    xmlSecAssert2(dsigCtx->status == xmlSecDSigStatusUnknown, -1);
    xmlSecAssert2(dsigCtx->signMethod == NULL, -1);
    xmlSecAssert2(dsigCtx->c14nMethod == NULL, -1);
    xmlSecAssert2((dsigCtx->operation == xmlSecTransformOperationSign) || (dsigCtx->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecPtrListGetSize(&(dsigCtx->signedInfoReferences)) == 0, -1);
    xmlSecAssert2(node != NULL, -1);
    
    /* first node is required CanonicalizationMethod. */
    cur = xmlSecGetNextElementNode(node->children);
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeCanonicalizationMethod, xmlSecDSigNs))) {
	dsigCtx->c14nMethod = xmlSecTransformCtxNodeRead(&(dsigCtx->transformCtx), 
					cur, xmlSecTransformUsageC14NMethod);
	if(dsigCtx->c14nMethod == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCtxNodeRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(cur)));
	    return(-1);	
	}	
    } else if(dsigCtx->defC14NMethodId != xmlSecTransformIdUnknown) {
	/* the dsig spec does require CanonicalizationMethod node
	 * to be present but in some case it application might decide to
	 * minimize traffic */
	dsigCtx->c14nMethod = xmlSecTransformCtxCreateAndAppend(&(dsigCtx->transformCtx), 
							      dsigCtx->defC14NMethodId);
	if(dsigCtx->c14nMethod == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCtxAppend",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    } else {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "expected=%s",
		    xmlSecErrorsSafeString(xmlSecNodeCanonicalizationMethod));
	return(-1);
    }	
    
    /* insert membuf if requested */
    if((dsigCtx->flags & XMLSEC_DSIG_FLAGS_STORE_SIGNATURE) != 0) {
	xmlSecAssert2(dsigCtx->preSignMemBufMethod == NULL, -1);
	dsigCtx->preSignMemBufMethod = xmlSecTransformCtxCreateAndAppend(&(dsigCtx->transformCtx), 
						xmlSecTransformMemBufId);
	if(dsigCtx->preSignMemBufMethod == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCtxCreateAndAppend",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformMemBufId)));
	}
    }
        
    /* next node is required SignatureMethod. */
    cur = xmlSecGetNextElementNode(cur->next);
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeSignatureMethod, xmlSecDSigNs))) {
	dsigCtx->signMethod = xmlSecTransformCtxNodeRead(&(dsigCtx->transformCtx), 
					cur, xmlSecTransformUsageSignatureMethod);
	if(dsigCtx->signMethod == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCtxNodeRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(cur)));
	    return(-1);	
	}	
    } else if(dsigCtx->defSignMethodId != xmlSecTransformIdUnknown) {
	/* the dsig spec does require SignatureMethod node
	 * to be present but in some case it application might decide to
	 * minimize traffic */
	dsigCtx->signMethod = xmlSecTransformCtxCreateAndAppend(&(dsigCtx->transformCtx), 
							      dsigCtx->defSignMethodId);
	if(dsigCtx->signMethod == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCtxAppend",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    } else {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "expected=%s",
		    xmlSecErrorsSafeString(xmlSecNodeSignatureMethod));
	return(-1);
    }	
    dsigCtx->signMethod->operation = dsigCtx->operation;
    
    /* calculate references */
    cur = xmlSecGetNextElementNode(cur->next);
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeReference, xmlSecDSigNs))) {
        /* create reference */
	dsigRefCtx = xmlSecDSigReferenceCtxCreate(dsigCtx, xmlSecDSigReferenceOriginSignedInfo);
	if(dsigRefCtx == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
		        "xmlSecDSigReferenceCtxCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);	    
	}

	/* add to the list */
	ret = xmlSecPtrListAdd(&(dsigCtx->signedInfoReferences), dsigRefCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecPtrListAdd",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecDSigReferenceCtxDestroy(dsigRefCtx);
	    return(-1);	    
	}

	/* process */
	ret = xmlSecDSigReferenceCtxProcessNode(dsigRefCtx, cur);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecDSigReferenceCtxProcessNode",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(cur)));
	    return(-1);	    
	}

	/* bail out if next Reference processing failed */
	if(dsigRefCtx->status != xmlSecDSigStatusSucceeded) {
	    dsigCtx->status = xmlSecDSigStatusInvalid;
	    return(0); 
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }

    /* check that we have at least one Reference */
    if(xmlSecPtrListGetSize(&(dsigCtx->signedInfoReferences)) == 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_DSIG_NO_REFERENCES,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* if there is something left than it's an error */
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

static int 
xmlSecDSigCtxProcessKeyInfoNode(xmlSecDSigCtxPtr dsigCtx, xmlNodePtr node) {
    int ret;
    
    xmlSecAssert2(dsigCtx != NULL, -1);
    xmlSecAssert2(dsigCtx->signMethod != NULL, -1);

    /* set key requirements */
    ret = xmlSecTransformSetKeyReq(dsigCtx->signMethod, &(dsigCtx->keyInfoReadCtx.keyReq));
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformSetKeyReq",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(dsigCtx->signMethod)));
	return(-1);
    }	
    
    /* ignore <dsig:KeyInfo /> if there is the key is already set */
    /* todo: throw an error if key is set and node != NULL? */
    if((dsigCtx->signKey == NULL) && (dsigCtx->keyInfoReadCtx.keysMngr != NULL) 
			&& (dsigCtx->keyInfoReadCtx.keysMngr->getKey != NULL)) {	
	dsigCtx->signKey = (dsigCtx->keyInfoReadCtx.keysMngr->getKey)(node, &(dsigCtx->keyInfoReadCtx));
    }
    
    /* check that we have exactly what we want */
    if((dsigCtx->signKey == NULL) || (!xmlSecKeyMatch(dsigCtx->signKey, NULL, &(dsigCtx->keyInfoReadCtx.keyReq)))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_KEY_NOT_FOUND,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    /* set the key to the transform */
    ret = xmlSecTransformSetKey(dsigCtx->signMethod, dsigCtx->signKey);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformSetKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(dsigCtx->signMethod)));
	return(-1);
    }

    /* if we are signing document, update <dsig:KeyInfo/> node */
    if((node != NULL) && (dsigCtx->operation == xmlSecTransformOperationSign)) {	
	ret = xmlSecKeyInfoNodeWrite(node, dsigCtx->signKey, &(dsigCtx->keyInfoWriteCtx));
	if(ret < 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeyInfoNodeWrite",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}	
    }
    
    return(0);
}

/**
 * xmlSecDSigCtxProcessObjectNode:
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
xmlSecDSigCtxProcessObjectNode(xmlSecDSigCtxPtr dsigCtx, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(dsigCtx != NULL, -1);	
    xmlSecAssert2(dsigCtx->status == xmlSecDSigStatusUnknown, -1);
    xmlSecAssert2(node != NULL, -1);
    
    /* we care about Manifest nodes only; ignore everything else */
    cur = xmlSecGetNextElementNode(node->children);
    while(cur != NULL) {
	if(xmlSecCheckNodeName(cur, xmlSecNodeManifest, xmlSecDSigNs)) {
	    ret = xmlSecDSigCtxProcessManifestNode(dsigCtx, cur);
	    if(ret < 0){
    		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlSecDSigCtxProcessManifestNode",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);	    
	    }
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    return(0);
}

/**
 * xmlSecDSigCtxProcessManifestNode: 
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
xmlSecDSigCtxProcessManifestNode(xmlSecDSigCtxPtr dsigCtx, xmlNodePtr node) {
    xmlSecDSigReferenceCtxPtr dsigRefCtx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(dsigCtx != NULL, -1);	
    xmlSecAssert2(dsigCtx->status == xmlSecDSigStatusUnknown, -1);
    xmlSecAssert2(node != NULL, -1);

    /* calculate references */
    cur = xmlSecGetNextElementNode(node->children);
    while((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeReference, xmlSecDSigNs))) {
        /* create reference */
	dsigRefCtx = xmlSecDSigReferenceCtxCreate(dsigCtx, xmlSecDSigReferenceOriginManifest);
	if(dsigRefCtx == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
		        "xmlSecDSigReferenceCtxCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);	    
	}

	/* add to the list */
	ret = xmlSecPtrListAdd(&(dsigCtx->manifestReferences), dsigRefCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecPtrListAdd",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecDSigReferenceCtxDestroy(dsigRefCtx);
	    return(-1);	    
	}

	/* process */
	ret = xmlSecDSigReferenceCtxProcessNode(dsigRefCtx, cur);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecDSigReferenceCtxProcessNode",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(cur)));
	    return(-1);	    
	}

	/* we don;t care if Reference processing failed because
	 * it's Manifest node */
	cur = xmlSecGetNextElementNode(cur->next);
    }

    /* we should have nothing else here */
    if(cur != NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    
    return(0);
}

/**
 * xmlSecDSigCtxDebugDump:
 * @dsigCtx:		the pointer to <dsig:Signature/> processing context.
 * @output:		the pointer to output FILE.
 *
 * Prints the debug information about @dsigCtx to @output.
 */
void 
xmlSecDSigCtxDebugDump(xmlSecDSigCtxPtr dsigCtx, FILE* output) {
    xmlSecAssert(dsigCtx != NULL);
    xmlSecAssert(output != NULL);

    if(dsigCtx->operation == xmlSecTransformOperationSign) {    
	fprintf(output, "= SIGNATURE CONTEXT\n");
    } else {
	fprintf(output, "= VERIFICATION CONTEXT\n");
    }
    switch(dsigCtx->status) {
	case xmlSecDSigStatusUnknown:
	    fprintf(output, "== Status: unknown\n");
	    break;
	case xmlSecDSigStatusSucceeded:
	    fprintf(output, "== Status: succeeded\n");
	    break;
	case xmlSecDSigStatusInvalid:
	    fprintf(output, "== Status: invalid\n");
	    break;
    }
    fprintf(output, "== flags: 0x%08x\n", dsigCtx->flags);
    fprintf(output, "== flags2: 0x%08x\n", dsigCtx->flags2);

    if(dsigCtx->id != NULL) {
	fprintf(output, "== Id: \"%s\"\n", dsigCtx->id);
    }
    
    fprintf(output, "== Key Info Read Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(dsigCtx->keyInfoReadCtx), output);
    fprintf(output, "== Key Info Write Ctx:\n");
    xmlSecKeyInfoCtxDebugDump(&(dsigCtx->keyInfoWriteCtx), output);

    fprintf(output, "== Signature Transform Ctx:\n");
    xmlSecTransformCtxDebugDump(&(dsigCtx->transformCtx), output);

    if(dsigCtx->signMethod != NULL) {
        fprintf(output, "== Signature Method:\n");
	xmlSecTransformDebugDump(dsigCtx->signMethod, output);
    }

    if(dsigCtx->signKey != NULL) {
        fprintf(output, "== Signature Key:\n");
	xmlSecKeyDebugDump(dsigCtx->signKey, output);
    }
    
    fprintf(output, "== SignedInfo References List:\n");
    xmlSecPtrListDebugDump(&(dsigCtx->signedInfoReferences), output);

    fprintf(output, "== Manifest References List:\n");
    xmlSecPtrListDebugDump(&(dsigCtx->manifestReferences), output);
    
    if((dsigCtx->result != NULL) && 
       (xmlSecBufferGetData(dsigCtx->result) != NULL)) {

	fprintf(output, "== Result - start buffer:\n");
	fwrite(xmlSecBufferGetData(dsigCtx->result), 
	       xmlSecBufferGetSize(dsigCtx->result), 
	       1, output);
	fprintf(output, "\n== Result - end buffer\n");
    }
    if(((dsigCtx->flags & XMLSEC_DSIG_FLAGS_STORE_SIGNATURE) != 0) &&
       (xmlSecDSigCtxGetPreSignBuffer(dsigCtx) != NULL) &&
       (xmlSecBufferGetData(xmlSecDSigCtxGetPreSignBuffer(dsigCtx)) != NULL)) {
       
	fprintf(output, "== PreSigned data - start buffer:\n");
	fwrite(xmlSecBufferGetData(xmlSecDSigCtxGetPreSignBuffer(dsigCtx)), 
	       xmlSecBufferGetSize(xmlSecDSigCtxGetPreSignBuffer(dsigCtx)), 
	       1, output);
	fprintf(output, "\n== PreSigned data - end buffer\n");       
    }
}

/**
 * xmlSecDSigCtxDebugXmlDump:
 * @dsigCtx:		the pointer to <dsig:Signature/> processing context.
 * @output:		the pointer to output FILE.
 *
 * Prints the debug information about @dsigCtx to @output in XML format.
 */
void 
xmlSecDSigCtxDebugXmlDump(xmlSecDSigCtxPtr dsigCtx, FILE* output) {
    xmlSecAssert(dsigCtx != NULL);
    xmlSecAssert(output != NULL);

    if(dsigCtx->operation == xmlSecTransformOperationSign) {    
	fprintf(output, "<SignatureContext \n");
    } else {
	fprintf(output, "<VerificationContext \n");
    }
    switch(dsigCtx->status) {
	case xmlSecDSigStatusUnknown:
	    fprintf(output, "status=\"unknown\" >\n");
	    break;
	case xmlSecDSigStatusSucceeded:
	    fprintf(output, "status=\"succeeded\" >\n");
	    break;
	case xmlSecDSigStatusInvalid:
	    fprintf(output, "status=\"invalid\" >\n");
	    break;
    }

    fprintf(output, "<Flags>%08x</Flags>\n", dsigCtx->flags);
    fprintf(output, "<Flags2>%08x</Flags2>\n", dsigCtx->flags2);

    if(dsigCtx->id != NULL) {
	fprintf(output, "<Id>%s</Id>\n", dsigCtx->id);
    }

    fprintf(output, "<KeyInfoReadCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(dsigCtx->keyInfoReadCtx), output);
    fprintf(output, "</KeyInfoReadCtx>\n");

    fprintf(output, "<KeyInfoWriteCtx>\n");
    xmlSecKeyInfoCtxDebugXmlDump(&(dsigCtx->keyInfoWriteCtx), output);
    fprintf(output, "</KeyInfoWriteCtx>\n");

    fprintf(output, "<SignatureTransformCtx>\n");
    xmlSecTransformCtxDebugXmlDump(&(dsigCtx->transformCtx), output);
    fprintf(output, "</SignatureTransformCtx>\n");

    if(dsigCtx->signMethod != NULL) {
        fprintf(output, "<SignatureMethod>\n");
	xmlSecTransformDebugXmlDump(dsigCtx->signMethod, output);
        fprintf(output, "</SignatureMethod>\n");
    }

    if(dsigCtx->signKey != NULL) {
        fprintf(output, "<SignatureKey>\n");
	xmlSecKeyDebugXmlDump(dsigCtx->signKey, output);
        fprintf(output, "</SignatureKey>\n");
    }

    fprintf(output, "<SignedInfoReferences>\n");
    xmlSecPtrListDebugXmlDump(&(dsigCtx->signedInfoReferences), output);
    fprintf(output, "</SignedInfoReferences>\n");

    fprintf(output, "<ManifestReferences>\n");
    xmlSecPtrListDebugXmlDump(&(dsigCtx->manifestReferences), output);
    fprintf(output, "</ManifestReferences>\n");

    if((dsigCtx->result != NULL) && 
       (xmlSecBufferGetData(dsigCtx->result) != NULL)) {

	fprintf(output, "<Result>");
	fwrite(xmlSecBufferGetData(dsigCtx->result), 
	       xmlSecBufferGetSize(dsigCtx->result), 
	       1, output);
	fprintf(output, "</Result>\n");
    }
    if(((dsigCtx->flags & XMLSEC_DSIG_FLAGS_STORE_SIGNATURE) != 0) &&
       (xmlSecDSigCtxGetPreSignBuffer(dsigCtx) != NULL) &&
       (xmlSecBufferGetData(xmlSecDSigCtxGetPreSignBuffer(dsigCtx)) != NULL)) {
       
	fprintf(output, "<PreSignedData>");
	fwrite(xmlSecBufferGetData(xmlSecDSigCtxGetPreSignBuffer(dsigCtx)), 
	       xmlSecBufferGetSize(xmlSecDSigCtxGetPreSignBuffer(dsigCtx)), 
	       1, output);
	fprintf(output, "</PreSignedData>\n");       
    }

    if(dsigCtx->operation == xmlSecTransformOperationSign) {    
	fprintf(output, "</SignatureContext>\n");
    } else {
	fprintf(output, "</VerificationContext>\n");
    }
}

/**************************************************************************
 *
 * xmlSecDSigReferenceCtx
 *
 *************************************************************************/
/**
 * xmlSecDSigReferenceCtxCreate:
 * @dsigCtx:		the pointer to parent <dsig:Signature/> node processing context.
 * @origin:		the reference origin (<dsig:SignedInfo/> or <dsig:Manifest/> node).
 *
 * Creates new <dsig:Reference/> element processing context. Caller is responsible
 * for destroying the returned context by calling #xmlSecDSigReferenceCtxDestroy
 * function.
 *
 * Returns pointer to newly created context or NULL if an error occurs.
 */
xmlSecDSigReferenceCtxPtr	
xmlSecDSigReferenceCtxCreate(xmlSecDSigCtxPtr dsigCtx, xmlSecDSigReferenceOrigin origin) {
    xmlSecDSigReferenceCtxPtr dsigRefCtx;
    int ret;
    
    xmlSecAssert2(dsigCtx != NULL, NULL);
    
    dsigRefCtx = (xmlSecDSigReferenceCtxPtr) xmlMalloc(sizeof(xmlSecDSigReferenceCtx));
    if(dsigRefCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecDSigReferenceCtx)=%d", 
		    sizeof(xmlSecDSigReferenceCtx));
	return(NULL);
    }
    
    ret = xmlSecDSigReferenceCtxInitialize(dsigRefCtx, dsigCtx, origin);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecDSigReferenceCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecDSigReferenceCtxDestroy(dsigRefCtx);
	return(NULL);   
    }
    return(dsigRefCtx);    
}

/** 
 * xmlSecDSigReferenceCtxDestroy:
 * @dsigRefCtx:		the pointer to <dsig:Reference/> element processing context.
 *
 * Destroy context object created with #xmlSecDSigReferenceCtxCreate function.
 */
void  
xmlSecDSigReferenceCtxDestroy(xmlSecDSigReferenceCtxPtr dsigRefCtx) {
    xmlSecAssert(dsigRefCtx != NULL);
    
    xmlSecDSigReferenceCtxFinalize(dsigRefCtx);
    xmlFree(dsigRefCtx);
}

/**
 * xmlSecDSigReferenceCtxInitialize:
 * @dsigRefCtx:		the pointer to <dsig:Reference/> element processing context.
 * @dsigCtx:		the pointer to parent <dsig:Signature/> node processing context.
 * @origin:		the reference origin (<dsig:SignedInfo/> or <dsig:Manifest/> node).
 *
 * Initializes new <dsig:Reference/> element processing context. Caller is responsible
 * for cleaning up the returned context by calling #xmlSecDSigReferenceCtxFinalize
 * function.
 *
 * Returns 0 on succes or aa negative value otherwise.
 */
int 
xmlSecDSigReferenceCtxInitialize(xmlSecDSigReferenceCtxPtr dsigRefCtx, xmlSecDSigCtxPtr dsigCtx,
				xmlSecDSigReferenceOrigin origin) {
    int ret;
    
    xmlSecAssert2(dsigCtx != NULL, -1);
    xmlSecAssert2(dsigRefCtx != NULL, -1);
    
    memset(dsigRefCtx, 0, sizeof(xmlSecDSigReferenceCtx));
    
    dsigRefCtx->dsigCtx = dsigCtx;
    dsigRefCtx->origin = origin;
    
    /* initializes transforms dsigRefCtx */
    ret = xmlSecTransformCtxInitialize(&(dsigRefCtx->transformCtx));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);   
    }
    
    /* copy enabled transforms */
    if(dsigCtx->enabledReferenceTransforms != NULL) {
	ret = xmlSecPtrListCopy(&(dsigRefCtx->transformCtx.enabledTransforms), 
				     dsigCtx->enabledReferenceTransforms);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecPtrListCopy",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);   
	}
    }    
    dsigRefCtx->transformCtx.preExecCallback = dsigCtx->referencePreExecuteCallback;
    dsigRefCtx->transformCtx.enabledUris = dsigCtx->enabledReferenceUris;
    return(0);
}

/** 
 * xmlSecDSigReferenceCtxFinalize:
 * @dsigRefCtx:		the pointer to <dsig:Reference/> element processing context.
 *
 * Cleans up context object created with #xmlSecDSigReferenceCtxInitialize function.
 */
void 
xmlSecDSigReferenceCtxFinalize(xmlSecDSigReferenceCtxPtr dsigRefCtx) {
    xmlSecAssert(dsigRefCtx != NULL);

    xmlSecTransformCtxFinalize(&(dsigRefCtx->transformCtx));
    if(dsigRefCtx->id != NULL) {
	xmlFree(dsigRefCtx->id);
    }	
    if(dsigRefCtx->uri != NULL) {
	xmlFree(dsigRefCtx->uri);
    }	
    if(dsigRefCtx->type != NULL) {
	xmlFree(dsigRefCtx->type);
    }	
    memset(dsigRefCtx, 0, sizeof(xmlSecDSigReferenceCtx));
}

/**
 * xmlSecDSigReferenceCtxGetPreDigestBuffer:
 * @dsigRefCtx:		the pointer to <dsig:Reference/> element processing context.
 * 
 * Gets the results of <dsig:Reference/> node processing just before digesting
 * (valid only if #XMLSEC_DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES or
 * #XMLSEC_DSIG_FLAGS_STORE_MANIFEST_REFERENCES flas of signature context
 * is set).
 *
 * Returns pointer to the buffer or NULL if an error occurs.
 */
xmlSecBufferPtr 
xmlSecDSigReferenceCtxGetPreDigestBuffer(xmlSecDSigReferenceCtxPtr dsigRefCtx) {
    xmlSecAssert2(dsigRefCtx != NULL, NULL);
    
    return((dsigRefCtx->preDigestMemBufMethod != NULL) ? 
	    xmlSecTransformMemBufGetBuffer(dsigRefCtx->preDigestMemBufMethod) : NULL);
}

/**
 * xmlSecDSigReferenceCtxProcessNode:
 * @dsigRefCtx:		the pointer to <dsig:Reference/> element processing context.
 * @node:		the pointer to <dsig:Reference/> node.

 * The Reference Element (http://www.w3.org/TR/xmldsig-core/#sec-Reference)
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
 * Returns 0 on succes or aa negative value otherwise.
 */
int 
xmlSecDSigReferenceCtxProcessNode(xmlSecDSigReferenceCtxPtr dsigRefCtx, xmlNodePtr node) {
    xmlSecTransformCtxPtr transformCtx;
    xmlNodePtr digestValueNode;
    xmlNodePtr cur;
    int ret;
    
    xmlSecAssert2(dsigRefCtx != NULL, -1);
    xmlSecAssert2(dsigRefCtx->dsigCtx != NULL, -1);
    xmlSecAssert2(dsigRefCtx->digestMethod == NULL, -1);
    xmlSecAssert2(dsigRefCtx->digestMethod == NULL, -1);
    xmlSecAssert2(dsigRefCtx->preDigestMemBufMethod == NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(node->doc != NULL, -1);

    transformCtx = &(dsigRefCtx->transformCtx);

    /* read attributes first */
    dsigRefCtx->uri = xmlGetProp(node, xmlSecAttrURI);
    dsigRefCtx->id  = xmlGetProp(node, xmlSecAttrId);
    dsigRefCtx->type= xmlGetProp(node, xmlSecAttrType);

    /* set start URI (and check that it is enabled!) */
    ret = xmlSecTransformCtxSetUri(transformCtx, dsigRefCtx->uri, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCtxSetUri",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "uri=%s",
		    xmlSecErrorsSafeString(dsigRefCtx->uri));
	return(-1);
    }

    /* first is optional Transforms node */
    cur = xmlSecGetNextElementNode(node->children);
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeTransforms, xmlSecDSigNs))) {
	ret = xmlSecTransformCtxNodesListRead(transformCtx, 
					cur, xmlSecTransformUsageDSigTransform);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCtxNodesListRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(cur)));
	    return(-1);
	}	
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* insert membuf if requested */
    if(((dsigRefCtx->origin == xmlSecDSigReferenceOriginSignedInfo) &&
	((dsigRefCtx->dsigCtx->flags & XMLSEC_DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES) != 0)) ||
       ((dsigRefCtx->origin == xmlSecDSigReferenceOriginManifest) &&
	((dsigRefCtx->dsigCtx->flags & XMLSEC_DSIG_FLAGS_STORE_MANIFEST_REFERENCES) != 0))) {

	xmlSecAssert2(dsigRefCtx->preDigestMemBufMethod == NULL, -1);
	dsigRefCtx->preDigestMemBufMethod = xmlSecTransformCtxCreateAndAppend(
						transformCtx, 
						xmlSecTransformMemBufId);
	if(dsigRefCtx->preDigestMemBufMethod == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCtxCreateAndAppend",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformMemBufId)));
	    return(-1);
	}
    }
        
    /* next node is required DigestMethod. */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDigestMethod, xmlSecDSigNs))) {
	dsigRefCtx->digestMethod = xmlSecTransformCtxNodeRead(&(dsigRefCtx->transformCtx), 
					cur, xmlSecTransformUsageDigestMethod);
	if(dsigRefCtx->digestMethod == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCtxNodeRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(cur)));
	    return(-1);	
	}	
    } else if(dsigRefCtx->dsigCtx->defSignMethodId != xmlSecTransformIdUnknown) {
	/* the dsig spec does require DigestMethod node
	 * to be present but in some case it application might decide to
	 * minimize traffic */
	dsigRefCtx->digestMethod = xmlSecTransformCtxCreateAndAppend(&(dsigRefCtx->transformCtx), 
							      dsigRefCtx->dsigCtx->defSignMethodId);
	if(dsigRefCtx->digestMethod == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCtxAppend",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    } else {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "expected=%s",
		    xmlSecErrorsSafeString(xmlSecNodeDigestMethod));
	return(-1);
    }	
    dsigRefCtx->digestMethod->operation = dsigRefCtx->dsigCtx->operation;

    /* last node is required DigestValue */
    cur = xmlSecGetNextElementNode(cur->next);     
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDigestValue, xmlSecDSigNs))) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeDigestValue));
	return(-1);
    }
    digestValueNode = cur;
    cur = xmlSecGetNextElementNode(cur->next);     

    /* if we have something else then it's an error */
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* if we need to write result to xml node then we need base64 encode result */
    if(dsigRefCtx->dsigCtx->operation == xmlSecTransformOperationSign) {	
	xmlSecTransformPtr base64Encode;
	
	/* we need to add base64 encode transform */
	base64Encode = xmlSecTransformCtxCreateAndAppend(transformCtx, xmlSecTransformBase64Id);
    	if(base64Encode == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCtxCreateAndAppend",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	base64Encode->operation = xmlSecTransformOperationEncode;
    }

    /* finally get transforms results */
    ret = xmlSecTransformCtxExecute(transformCtx, node->doc);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCtxExecute",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    
    dsigRefCtx->result = transformCtx->result;

    if(dsigRefCtx->dsigCtx->operation == xmlSecTransformOperationSign) {	
	if((dsigRefCtx->result == NULL) || (xmlSecBufferGetData(dsigRefCtx->result) == NULL)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCtxExecute",
	    		XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	
	/* write signed data to xml */
	xmlNodeSetContentLen(digestValueNode,
			    xmlSecBufferGetData(dsigRefCtx->result),
			    xmlSecBufferGetSize(dsigRefCtx->result));
    
	/* set success status and we are done */
	dsigRefCtx->status = xmlSecDSigStatusSucceeded;
    } else {
	/* verify SignatureValue node content */
	ret = xmlSecTransformVerifyNodeContent(dsigRefCtx->digestMethod, 
			    digestValueNode, transformCtx);
	if(ret < 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformVerifyNodeContent",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    
        /* set status and we are done */
	if(dsigRefCtx->digestMethod->status == xmlSecTransformStatusOk) {
	    dsigRefCtx->status = xmlSecDSigStatusSucceeded;
	} else {
    	    dsigRefCtx->status = xmlSecDSigStatusInvalid;
	}
    }

    return(0);
}

/**
 * xmlSecDSigReferenceCtxDebugDump:
 * @dsigRefCtx:		the pointer to <dsig:Reference/> element processing context.
 * @output:		the pointer to output FILE.
 *
 * Prints debug information about @dsigRefCtx to @output.
 */
void 
xmlSecDSigReferenceCtxDebugDump(xmlSecDSigReferenceCtxPtr dsigRefCtx, FILE* output) {
    xmlSecAssert(dsigRefCtx != NULL);
    xmlSecAssert(dsigRefCtx->dsigCtx != NULL);
    xmlSecAssert(output != NULL);

    if(dsigRefCtx->dsigCtx->operation == xmlSecTransformOperationSign) {    
	fprintf(output, "= REFERENCE CALCULATION CONTEXT\n");
    } else {
	fprintf(output, "= REFERENCE VERIFICATION CONTEXT\n");
    }
    switch(dsigRefCtx->status) {
	case xmlSecDSigStatusUnknown:
	    fprintf(output, "== Status: unknown\n");
	    break;
	case xmlSecDSigStatusSucceeded:
	    fprintf(output, "== Status: succeeded\n");
	    break;
	case xmlSecDSigStatusInvalid:
	    fprintf(output, "== Status: invalid\n");
	    break;
    }
    if(dsigRefCtx->id != NULL) {
	fprintf(output, "== Id: \"%s\"\n", dsigRefCtx->id);
    }
    if(dsigRefCtx->uri != NULL) {
	fprintf(output, "== URI: \"%s\"\n", dsigRefCtx->uri);
    }
    if(dsigRefCtx->type != NULL) {
	fprintf(output, "== Type: \"%s\"\n", dsigRefCtx->type);
    }

    fprintf(output, "== Reference Transform Ctx:\n");
    xmlSecTransformCtxDebugDump(&(dsigRefCtx->transformCtx), output);

    if(dsigRefCtx->digestMethod != NULL) {
        fprintf(output, "== Digest Method:\n");
	xmlSecTransformDebugDump(dsigRefCtx->digestMethod, output);
    }

    if((xmlSecDSigReferenceCtxGetPreDigestBuffer(dsigRefCtx) != NULL) &&
       (xmlSecBufferGetData(xmlSecDSigReferenceCtxGetPreDigestBuffer(dsigRefCtx)) != NULL)) {
       
	fprintf(output, "== PreDigest data - start buffer:\n");
	fwrite(xmlSecBufferGetData(xmlSecDSigReferenceCtxGetPreDigestBuffer(dsigRefCtx)), 
	       xmlSecBufferGetSize(xmlSecDSigReferenceCtxGetPreDigestBuffer(dsigRefCtx)), 
	       1, output);
	fprintf(output, "\n== PreDigest data - end buffer\n");       
    }

    if((dsigRefCtx->result != NULL) && 
       (xmlSecBufferGetData(dsigRefCtx->result) != NULL)) {

	fprintf(output, "== Result - start buffer:\n");
	fwrite(xmlSecBufferGetData(dsigRefCtx->result), 
	       xmlSecBufferGetSize(dsigRefCtx->result), 1,
	       output);
	fprintf(output, "\n== Result - end buffer\n");
    }
}

/**
 * xmlSecDSigReferenceCtxDebugXmlDump:
 * @dsigRefCtx:		the pointer to <dsig:Reference/> element processing context.
 * @output:		the pointer to output FILE.
 *
 * Prints debug information about @dsigRefCtx to @output in output format.
 */
void 
xmlSecDSigReferenceCtxDebugXmlDump(xmlSecDSigReferenceCtxPtr dsigRefCtx, FILE* output) {
    xmlSecAssert(dsigRefCtx != NULL);
    xmlSecAssert(dsigRefCtx->dsigCtx != NULL);
    xmlSecAssert(output != NULL);

    if(dsigRefCtx->dsigCtx->operation == xmlSecTransformOperationSign) {    
	fprintf(output, "<ReferenceCalculationContext ");
    } else {
	fprintf(output, "<ReferenceVerificationContext ");
    }
    switch(dsigRefCtx->status) {
	case xmlSecDSigStatusUnknown:
	    fprintf(output, "status=\"unknown\" >\n");
	    break;
	case xmlSecDSigStatusSucceeded:
	    fprintf(output, "status=\"succeeded\" >\n");
	    break;
	case xmlSecDSigStatusInvalid:
	    fprintf(output, "status=\"invalid\" >\n");
	    break;
    }

    if(dsigRefCtx->id != NULL) {
	fprintf(output, "<Id>%s</Id>\n", dsigRefCtx->id);
    }
    if(dsigRefCtx->uri != NULL) {
	fprintf(output, "<URI>%s</URI>\n", dsigRefCtx->uri);
    }
    if(dsigRefCtx->type != NULL) {
	fprintf(output, "<Type>%s</Type>\n", dsigRefCtx->type);
    }

    fprintf(output, "<ReferenceTransformCtx>\n");
    xmlSecTransformCtxDebugXmlDump(&(dsigRefCtx->transformCtx), output);
    fprintf(output, "</ReferenceTransformCtx>\n");

    if(dsigRefCtx->digestMethod != NULL) {
        fprintf(output, "<DigestMethod>\n");
	xmlSecTransformDebugXmlDump(dsigRefCtx->digestMethod, output);
        fprintf(output, "</DigestMethod>\n");
    }

    if((dsigRefCtx->result != NULL) && 
       (xmlSecBufferGetData(dsigRefCtx->result) != NULL)) {

	fprintf(output, "<Result>");
	fwrite(xmlSecBufferGetData(dsigRefCtx->result), 
	       xmlSecBufferGetSize(dsigRefCtx->result), 1,
	       output);
	fprintf(output, "</Result>\n");
    }

    if((xmlSecDSigReferenceCtxGetPreDigestBuffer(dsigRefCtx) != NULL) &&
       (xmlSecBufferGetData(xmlSecDSigReferenceCtxGetPreDigestBuffer(dsigRefCtx)) != NULL)) {
       
	fprintf(output, "<PreDigestData>");
	fwrite(xmlSecBufferGetData(xmlSecDSigReferenceCtxGetPreDigestBuffer(dsigRefCtx)), 
	       xmlSecBufferGetSize(xmlSecDSigReferenceCtxGetPreDigestBuffer(dsigRefCtx)), 
	       1, output);
	fprintf(output, "</PreDigestData>\n");       
    }
    if(dsigRefCtx->dsigCtx->operation == xmlSecTransformOperationSign) {    
	fprintf(output, "</ReferenceCalculationContext>\n");
    } else {
	fprintf(output, "</ReferenceVerificationContext>\n");
    }
}


/**************************************************************************
 *
 * xmlSecDSigReferenceCtxListKlass
 *
 *************************************************************************/
static xmlSecPtrListKlass xmlSecDSigReferenceCtxListKlass = {
    BAD_CAST "dsig-reference-list",
    NULL,								/* xmlSecPtrDuplicateItemMethod duplicateItem; */
    (xmlSecPtrDestroyItemMethod)xmlSecDSigReferenceCtxDestroy,		/* xmlSecPtrDestroyItemMethod destroyItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecDSigReferenceCtxDebugDump,	/* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecDSigReferenceCtxDebugXmlDump,	/* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

/**
 * xmlSecDSigReferenceCtxListGetKlass:
 *
 * The <dsig:Reference/> element processing contexts list klass.
 *
 * Returns <dsig:Reference/> element processing context list klass.
 */
xmlSecPtrListId 
xmlSecDSigReferenceCtxListGetKlass(void) {
    return(&xmlSecDSigReferenceCtxListKlass);
}

#endif /* XMLSEC_NO_XMLDSIG */


