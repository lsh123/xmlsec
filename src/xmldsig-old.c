    /* next node is required SignatureValue */
/**
 * xmlSecSignedInfoCalculate:
 *
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
		    NULL,
		    "xmlSecNodeSetGetChildren",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeGetName(signedInfoNode)));
	goto done;
    }

    state = xmlSecTransformStateCreate(signedInfoNode->doc, nodeSet, NULL);
    if(state == NULL){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformStateCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }	

    ret = xmlSecTransformStateUpdate(state, c14nMethod);
    if(ret < 0){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformStateUpdate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(c14nMethod)));
	goto done;
    }

    /* 
     * if requested then insert a memory buffer to capture the digest data 
     */
    if(result->ctx->storeSignatures || result->ctx->fakeSignatures) {
	memBuffer = xmlSecTransformCreate(xmlSecTransformMemBufId, 1);
	if(memBuffer == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformMemBufId)));
	    goto done;
	}
	ret = xmlSecTransformStateUpdate(state, memBuffer);
	if(ret < 0){
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformStateUpdate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformGetName(memBuffer)));
	    goto done;
	}
    }
     
    if(!(result->ctx->fakeSignatures)) {
	ret = xmlSecTransformStateUpdate(state, signMethod);
	if(ret < 0){
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformStateUpdate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformGetName(signMethod)));
	    goto done;
	}
	signMethod->encode = sign;

	if(sign) {
	    ret = xmlSecTransformStateFinalToNode(state, signatureValueNode, 1, 
						&transformCtx);
	    if(ret < 0) {    
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlSecTransformStateFinalToNode",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
	        goto done;
	    }
        } else {
    	    ret = xmlSecTransformStateFinalVerifyNode(state, signMethod, 
						signatureValueNode, &transformCtx);
	    if(ret < 0) {    
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlSecTransformStateFinalVerifyNode",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		goto done;
	    }
	}	
	result->result = signMethod->status;
    } else {
	result->result = xmlSecTransformStatusOk; /* in "fake" mode we always ok */
    }

    if(memBuffer != NULL) {
	result->buffer = xmlSecTransformMemBufGetBuffer(memBuffer, 1);
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



static int
xmlSecSignedInfoRead(xmlNodePtr signedInfoNode,  int sign,
	   	      xmlNodePtr signatureValueNode, xmlNodePtr keyInfoNode,
		      xmlSecDSigResultPtr result) {
    xmlSecTransformCtx transformCtx;
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
    
    /* next is Reference nodes (at least one must present!) */
    while((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeReference, xmlSecDSigNs)) {
	ref = xmlSecReferenceCreate(xmlSecSignedInfoReference, 
				     result->ctx, cur);
	if(ref == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecReferenceCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    goto done;
	}
	
	ret = xmlSecReferenceRead(ref, cur, sign);
	if(ret < 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecReferenceRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecReferenceDestroy(ref);
	    goto done;
	}
	
	if(xmlSecDSigResultAddSignedInfoRef(result, ref) == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecDSigResultAddSignedInfoRef",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecReferenceDestroy(ref);
	    goto done;
	}	


	if((!sign) && (ref->result != xmlSecTransformStatusOk)) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			NULL,
			XMLSEC_ERRORS_R_DSIG_INVALID_REFERENCE,
			XMLSEC_ERRORS_NO_MESSAGE);
	    /* "soft" error */
	    res = 0;
	    goto done;
	}
	cur = xmlSecGetNextElementNode(cur->next); 
    }
    
    if(result->firstSignRef == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "Reference");
	goto done;
    }

    if(cur != NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    /* calculate result and write/verify it*/
    ret = xmlSecSignedInfoCalculate(signedInfoNode, sign,
				    c14nMethod, signMethod, 
				    signatureValueNode, result);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecSignedInfoCalculate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
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
    ref->uri = xmlGetProp(self, xmlSecAttrURI);
    ref->id  = xmlGetProp(self, xmlSecAttrId);
    ref->type= xmlGetProp(self, xmlSecAttrType);

    state = xmlSecTransformStateCreate(self->doc, NULL, (char*)ref->uri);
    if(state == NULL){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformStateCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "uri=%s",
		    xmlSecErrorsSafeString(ref->uri));
	goto done;
    }	

    /* first is optional Transforms node */
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeTransforms, xmlSecDSigNs)) {
	ret = xmlSecTransformsNodeRead(state, cur);
	if(ret < 0){
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformsNodeRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    goto done;
	}	
	cur = xmlSecGetNextElementNode(cur->next);
    }

    /* 
     * if requested then insert a memory buffer to capture the digest data 
     */
    if(ref->ctx->storeReferences) {
	memBuffer = xmlSecTransformCreate(xmlSecTransformMemBufId, 1);
	if(memBuffer == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformMemBufId)));
	    goto done;
	}
	ret = xmlSecTransformStateUpdate(state, memBuffer);
	if(ret < 0){
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformStateUpdate",			
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformMemBufId)));
	    goto done;
	}
    }
     
    /* next node is required DigestMethod */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDigestMethod, xmlSecDSigNs))) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s",
		    xmlSecErrorsSafeString(xmlSecNodeDigestMethod));
	goto done;
    }
    digestMethod = xmlSecTransformNodeRead(cur, xmlSecTransformUsageDigestMethod, &transformCtx);
    if(digestMethod == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformNodeRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }
    digestMethod->dontDestroy = 1;
    digestMethod->encode = sign;
    
    ret = xmlSecTransformStateUpdate(state, digestMethod);
    if(ret < 0){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformStateUpdate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(digestMethod)));
	goto done;
    }
    ref->digestMethod = digestMethod->id;
    cur = xmlSecGetNextElementNode(cur->next);

    /* next node is required DigestValue */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDigestValue, xmlSecDSigNs))) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s",
		    xmlSecErrorsSafeString(xmlSecNodeDigestValue));
	goto done;
    }
    digestValueNode = cur;
    cur = xmlSecGetNextElementNode(cur->next);     

    if(cur != NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }
    
    if(sign) {
	ret = xmlSecTransformStateFinalToNode(state, digestValueNode, 1, &transformCtx);
	if(ret < 0) {    
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformStateFinalToNode",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    goto done;
	}
    } else {
	ret = xmlSecTransformStateFinalVerifyNode(state, digestMethod, digestValueNode, &transformCtx);
	if(ret < 0) {    
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformStateFinalVerifyNode",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"digest=%s",
			xmlSecErrorsSafeString(xmlSecTransformGetName(digestMethod)));
	    goto done;
	}
    }	
    ref->result = digestMethod->status;
    
    if(memBuffer != NULL) {
	ref->buffer = xmlSecTransformMemBufGetBuffer(memBuffer, 1);
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
xmlSecReferenceCreate(xmlSecReferenceType type, xmlSecDSigOldCtxPtr ctx, xmlNodePtr self) {
    xmlSecReferenceResultPtr ref;
        
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(self != NULL, NULL);

    /*
     * Allocate a new xmlSecReference and fill the fields.
     */
    ref = (xmlSecReferenceResultPtr) xmlMalloc(sizeof(xmlSecReferenceResult));
    if(ref == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlMalloc",
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
	if(xmlSecCheckNodeName(cur, xmlSecNodeManifest, xmlSecDSigNs)) {
	    ret = xmlSecManifestRead(cur, sign, result);
	    if(ret < 0){
    		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlSecManifestRead",
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
    while((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeReference, xmlSecDSigNs)) { 
	ref = xmlSecReferenceCreate(xmlSecManifestReference, 
				     result->ctx, cur);
	if(ref == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecReferenceCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	
	ret = xmlSecReferenceRead(ref, cur, sign);
	if(ret < 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecReferenceRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecReferenceDestroy(ref);
	    return(-1);
	}
	
	if(xmlSecDSigResultAddManifestRef(result, ref) == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecDSigResultAddManifestRef",		
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecReferenceDestroy(ref);
	    return(-1);
	}	
	cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    
    return(0);
}


