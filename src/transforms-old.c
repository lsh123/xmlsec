#include <xmlsec/transformsInternal.h>

static xmlSecTransformId xmlSecAllTransformIds[100];

/* internal functions */
static int  xmlSecTransformStateParseUri(xmlSecTransformStatePtr state, const char *uri);
static void xmlSecTransformStateDestroyCurrentDoc(xmlSecTransformStatePtr state);
static int  xmlSecTransformCreateXml(xmlSecTransformStatePtr state);
static int  xmlSecTransformCreateBin(xmlSecTransformStatePtr state);
static int  xmlSecTransformCreateBinFromXml(xmlSecTransformStatePtr state);
static int  xmlSecTransformCreateBinFromUri(xmlSecTransformStatePtr state);
static int xmlSecTransformPreBase64Decode(const xmlNodePtr node, xmlSecNodeSetPtr nodeSet, 
					  xmlOutputBufferPtr output);

/**********************************************************************
 *
 * Hi-level functions
 *
 *********************************************************************/
/**
 * xmlSecTransformsInit:
 *
 * Trnasforms engine initialization (called from xmlSecInit() function).
 * The applications should not call this function directly.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecTransformsInit(void) {
    memset(xmlSecAllTransformIds, 0, sizeof(xmlSecAllTransformIds));
    xmlSecAllTransformIds[0] = xmlSecTransformIdUnknown;
    
    /* encoding */
    if(xmlSecTransformRegister(xmlSecTransformBase64Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformRegister",	    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformBase64Id)));
	return(-1);
    }

    /* c14n methods */
    if(xmlSecTransformRegister(xmlSecC14NInclusive) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformRegister",	    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecC14NInclusive)));
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecC14NInclusiveWithComments) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformRegister",	    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecC14NInclusiveWithComments)));
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecC14NExclusive) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformRegister",	    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecC14NExclusive)));
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecC14NExclusiveWithComments) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformRegister",	    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecC14NExclusiveWithComments)));
	return(-1);
    }

    /* XML transforms */
    if(xmlSecTransformRegister(xmlSecTransformEnveloped) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformRegister",	    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformEnveloped)));
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecTransformXPath) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformRegister",	    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformXPath)));
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecTransformXPath2) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformRegister",	    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformXPath2)));
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecTransformXPointer) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformRegister",	    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformXPointer)));
	return(-1);
    }

#ifndef XMLSEC_NO_XSLT
    if(xmlSecTransformRegister(xmlSecTransformXsltId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformRegister",	    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformXsltId)));
	return(-1);
    }
#endif /* XMLSEC_NO_XSLT */    
    
    return(0);
}

/**
 * xmlSecTransformRegister:
 * @transformId: the transform id to register.
 *
 * Adds the @transformId to the internal table of known transforms.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformRegister(xmlSecTransformId keyId) {
    unsigned int i;
    
    xmlSecAssert2(keyId != NULL, -1);
    
    for(i = 0; i < sizeof(xmlSecAllTransformIds) / sizeof(xmlSecAllTransformIds[0]) - 1; ++i) {
	if(xmlSecAllTransformIds[i] == xmlSecTransformIdUnknown) {
	    xmlSecAllTransformIds[i++] = keyId;
	    xmlSecAllTransformIds[i++] = xmlSecTransformIdUnknown;
	    
	    return(0);
	}
    }
    
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		NULL,
		XMLSEC_ERRORS_R_XMLSEC_FAILED,
		"no more key slots available; increase xmlSecAllTransformIds table size");
    return(-1);
}


/**
 * xmlSecTransformsNodeRead:
 * @state: the pointer to current transform state.
 * @transformsNode: the pointer to the <dsig:Transform> node.
 *
 * Reads the transform node and updates @state,
 *
 * Returns 0 on success or a negative value otherwise.
 */ 
int
xmlSecTransformsNodeRead(xmlSecTransformStatePtr state, 
			 xmlNodePtr transformsNode) {
    xmlNodePtr cur;
    xmlSecTransformPtr transform;
    int ret;    

    xmlSecAssert2(state != NULL, -1);        
    xmlSecAssert2(transformsNode != NULL, -1);
    
    cur = xmlSecGetNextElementNode(transformsNode->children);
    while((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "Transform", xmlSecDSigNs)) {
	transform = xmlSecTransformNodeRead(cur, xmlSecTransformUsageDSigTransform, 0);
	if(transform == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformNodeRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(cur)));
	    return(-1);
	}
	ret = xmlSecTransformStateUpdate(state, transform);
	if(ret < 0){
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformStateUpdate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)));
	    xmlSecTransformDestroy(transform, 1);
	    return(-1);
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }

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
 * xmlSecTransformNodeRead:
 * @transformNode: the pointer to <dsig:Transform> node.
 * @usage: the usage of the transfomr (signature, encryption, etc.).
 * @dontDestroy: the flag whether we need to destroy the transform.
 *
 * Reads transform from the @transformNode as follows:
 *    1) reads "Algorithm" attribute;
 *    2) checks the list of known algorithms;
 *    3) calls transform create method;
 *    4) calls transform read transform node method.
 *
 * Returns the pointer to newly allocated #xmlSecTransform structure
 * or NULL if an error occurs.
 */
xmlSecTransformPtr	
xmlSecTransformNodeRead(xmlNodePtr transformNode, xmlSecTransformUsage usage,
			int dontDestroy) {
    xmlChar *href;
    xmlSecTransformId id;
    xmlSecTransformPtr transform;
    int ret;
    
    xmlSecAssert2(transformNode != NULL, NULL);
    
    href = xmlGetProp(transformNode, xmlSecAttrAlgorithm);
    if(href == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlGetProp",
		    XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecAttrAlgorithm));
	return(NULL);		
    }
    
    id = xmlSecTransformFind(href, usage);    
    if(id == xmlSecTransformIdUnknown) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformFind",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "href=\"%s\"", 
		    xmlSecErrorsSafeString(href));
	xmlFree(href);
	return(NULL);		
    }
    
    transform = xmlSecTransformCreate(id, dontDestroy);
    if(!xmlSecTransformIsValid(transform)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCreate",		    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(id)));
	xmlFree(href);
	return(NULL);		
    }
    
    ret = xmlSecTransformRead(transform, transformNode);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)));
	xmlSecTransformDestroy(transform, 1);
	xmlFree(href);
	return(NULL);		
    }
    
    xmlFree(href);   
    return(transform);
}

/**
 * xmlSecTransformNodeWrite:
 * @transformNode: the pointer to <dsig:Transform> node.
 * @id: the transform id.
 *
 * Writes Agorithm attribute in the transform node.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecTransformNodeWrite(xmlNodePtr transformNode, xmlSecTransformId id) {
    xmlSecAssert2(transformNode != NULL, -1);
    xmlSecAssert2(id != NULL, -1);
    
    if(xmlSetProp(transformNode, xmlSecAttrAlgorithm, id->href) == NULL) {	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSetProp",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "name=%s,value=%s",
		    xmlSecErrorsSafeString(xmlSecAttrAlgorithm),
		    xmlSecErrorsSafeString(id->href));
	return(-1);	
    }

    return(0);
}

/**************************************************************************
 *
 * Transform Info
 *
 **************************************************************************/ 
/**
 * xmlSecTransformFind:
 * @href: the transform href.
 *
 * Searches the list of known transforms for transform with given href
 *
 * Returns the id of the found transform or NULL if an error occurs 
 * or transform is not found.
 */ 
xmlSecTransformId
xmlSecTransformFind(const xmlChar* href, xmlSecTransformUsage usage) {
    xmlSecTransformId *ptr;

    xmlSecAssert2(href != NULL, NULL);
    
    ptr = xmlSecAllTransformIds;
    while((*ptr) != xmlSecTransformIdUnknown) {
	if(((usage & (*ptr)->usage) != 0) && xmlStrEqual((*ptr)->href, href)) {
	    return(*ptr);
	}
	++ptr;
    }
    
    /* not found */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		NULL,
		XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		"href=%s", 
		xmlSecErrorsSafeString(href));
    return(xmlSecTransformIdUnknown);
}

/**********************************************************************
 *
 * Transform 
 *
 *********************************************************************/ 
/**********************************************************************
 *
 * Binary transform
 *
 *********************************************************************/ 


/***************************************************************************
 *
 * Transforms State
 *
 **************************************************************************/
/**
 * xmlSecTransformStateCreate:
 * @doc: the pointer to XML document that contains <dsig:Signature> node.
 * @nodeSet: the original nodes set.
 * @uri: the original uri.
 *
 * Creates new transform state.
 *
 * Returns pointer to newly allocated #xmlSecTransformState structure
 * or NULL if an error occurs.
 */
xmlSecTransformStatePtr	
xmlSecTransformStateCreate(xmlDocPtr doc, xmlSecNodeSetPtr nodeSet, 
			   const char *uri) {
    xmlSecTransformStatePtr state;
    int ret;

    /*
     * Allocate a new xmlSecTransformState and fill the fields.
     */
    state = (xmlSecTransformStatePtr) xmlMalloc(sizeof(xmlSecTransformState));
    if(state == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecTransformState)=%d",
		    sizeof(xmlSecTransformState));
	return(NULL);
    }
    memset(state, 0, sizeof(xmlSecTransformState));
    
    state->curBuf = xmlSecBufferCreate(0);
    if(state->curBuf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferCreate",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "size=%d", 0);
	xmlSecTransformStateDestroy(state);
        return(NULL);
    }

    state->initDoc = doc;
    state->initNodeSet = nodeSet;
    ret = xmlSecTransformStateParseUri(state, uri);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformStateParseUri",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "uri=\"%s\"", 
		    xmlSecErrorsSafeString(uri));
	xmlSecTransformStateDestroy(state);
    	return(NULL);
    }
        
    return(state);     
}

/**
 * xmlSecTransformStateDestroy:
 * @state: the pointer to #xmlSecTransformState structure.
 *
 * Destroys the transform state.
 */
void
xmlSecTransformStateDestroy(xmlSecTransformStatePtr state) {
    xmlSecAssert(state != NULL);

    xmlSecTransformStateDestroyCurrentDoc(state);
    if(state->curBuf != NULL) {
	xmlSecBufferDestroy(state->curBuf);
    }
    if(state->curFirstBinTransform != NULL) {
	xmlSecTransformDestroyAll(state->curFirstBinTransform);
    } else if(state->curLastBinTransform != NULL) {
	xmlSecTransformDestroyAll(state->curLastBinTransform); 
    }
    if(state->initUri != NULL) {
	xmlFree(state->initUri);
    }
    memset(state, 0, sizeof(xmlSecTransformState));
    xmlFree(state);    
}

/**
 * xmlSecTransformStateUpdate:
 * @state: the pointer to #xmlSecTransformState structure.
 * @transform: the pointer to #xmlSecTransform structure.
 *
 * Updates the current @state with @transform. Note all transforms are
 * applied immidiatelly.
 *
 * Returns 0 on success or negative value otherwise.
 */
int
xmlSecTransformStateUpdate(xmlSecTransformStatePtr state, 
			   xmlSecTransformPtr transform) {
    int ret;

    xmlSecAssert2(state != NULL, -1);
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    
    switch(transform->id->type) {
    case xmlSecTransformTypeBinary:     	
	/* simply add transform to the chain */
	transform = xmlSecTransformAddAfter(state->curLastBinTransform, 
					    transform);
	if(transform == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformAddAfter",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=\"%s\"",
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)));
	    return(-1);
	}
	if(state->curFirstBinTransform == NULL) {
	    state->curFirstBinTransform = transform;
	}
	state->curLastBinTransform = transform;
	break;
    case xmlSecTransformTypeXml: {
	xmlDocPtr doc;
	xmlSecNodeSetPtr nodes;
	
        ret = xmlSecTransformCreateXml(state);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCreateXml",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	
	doc = state->curDoc;
	nodes = state->curNodeSet;
	
	ret = xmlSecTransformExecuteXml(transform, state->initDoc, &doc, &nodes);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformExecuteXml",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)));
	    return(-1);
	}
	xmlSecTransformDestroy(transform, 0);
	if(doc != state->curDoc) {
	    xmlSecTransformStateDestroyCurrentDoc(state);
	} else if(nodes != state->curNodeSet) {
	    if((state->curNodeSet != NULL) && (state->curNodeSet != state->initNodeSet)) {
    		xmlSecNodeSetDestroy(state->curNodeSet);
	    }
	}	
	state->curDoc = doc;
	state->curNodeSet = nodes;
    	break;
	}
    case xmlSecTransformTypeC14N:
	ret = xmlSecTransformCreateXml(state);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCreateXml",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	state->curC14NTransform = transform;
	break;
    default:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "type=%d", transform->id->type);
	return(-1);	    
    }
    return(0);
}

/**
 * xmlSecTransformStateFinal:
 * @state: the pointer to #xmlSecTransformState structure.
 * @type: the desired final type.
 *
 * Finalazies transforms @state (applies all pending transforms) and 
 * creates a result of the desired @type.
 *
 * Returns 0 on success or negative value otherwise.
 */
int
xmlSecTransformStateFinal(xmlSecTransformStatePtr state, 
			  xmlSecTransformResult type) {
    int ret;

    xmlSecAssert2(state != NULL, -1);
    
    switch(type) {
    case xmlSecTransformResultBinary:
	ret = xmlSecTransformCreateBin(state);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCreateBin",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);	
	}
	break;
    case xmlSecTransformResultXml:
	ret = xmlSecTransformCreateXml(state);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCreateXml",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);	
	}
	break;
    default:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "type=%d", type);
	return(-1);	
    }    

    return(0);
}

/**
 * xmlSecTransformStateParseUri:
 *
 * Parses uri and loads the document if required:
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-ReferenceProcessingModel:
 *
 * The following examples demonstrate what the URI attribute identifies and
 * how it is dereferenced:
 *
 * - URI="http://example.com/bar.xml"
 * Identifies the octets that represent the external resource 
 * 'http://example.com/bar.xml', that is probably an XML document given 
 * its file extension. 
 * - URI="http://example.com/bar.xml#chapter1"
 * Identifies the element with ID attribute value 'chapter1' of the 
 * external XML resource 'http://example.com/bar.xml', provided as an 
 * octet stream. Again, for the sake of interoperability, the element 
 * identified as 'chapter1' should be obtained using an XPath transform 
 * rather than a URI fragment (barename XPointer resolution in external 
 * resources is not REQUIRED in this specification). 
 * - URI=""
 * Identifies the node-set (minus any comment nodes) of the XML resource 
 * containing the signature 
 * - URI="#chapter1"
 * Identifies a node-set containing the element with ID attribute value 
 * 'chapter1' of the XML resource containing the signature. XML Signature 
 * (and its applications) modify this node-set to include the element plus 
 * all descendents including namespaces and attributes -- but not comments.
 *
 */
static int 
xmlSecTransformStateParseUri(xmlSecTransformStatePtr state, const char *uri) {
    const char* xptr;

    xmlSecAssert2(state != NULL, -1);
    
    if(uri == NULL) {
	state->curDoc 	  = state->initDoc;
	state->curNodeSet = state->initNodeSet;
    } else if(strcmp(uri, "") == 0) {
	/* all nodes set but comments */
	state->curDoc 	  = state->initDoc;
	state->curNodeSet = xmlSecNodeSetGetChildren(state->initDoc, 
				xmlDocGetRootElement(state->initDoc), 
				0, 0);
	if(state->curNodeSet == NULL){
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecNodeSetGetChildren",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    } else if((xptr = strchr(uri, '#')) == NULL) {
        state->initUri = (char*)xmlStrdup(BAD_CAST uri);
	if(state->initUri == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlStrdup",
			XMLSEC_ERRORS_R_MALLOC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	/* simple URI -- do not load document for now */
    } else {
    	state->initUri = (char*)xmlStrndup(BAD_CAST uri, xptr - uri);
	if(state->initUri == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlStrndup",
			XMLSEC_ERRORS_R_MALLOC_FAILED,
			"size=%d", xptr - uri);
	    return(-1);
	}
	
        /* if the uri is not empty, need to load document */
	if(strlen(state->initUri) > 0) {
	    state->curDoc = xmlSecParseFile(state->initUri); 
	    if(state->curDoc == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlSecParseFile",
    			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "uri=\"%s\"", 
			    xmlSecErrorsSafeString(state->initUri));
		return(-1);	    
	    }
	} else {
	    state->curDoc = state->initDoc; 
	}

	/* 
	 * now evaluate xptr if it is present and does not 
	 * equal to everything
	 */
	if((xptr != NULL) && (strcmp(xptr, "#xpointer(/)") != 0)) {   
            xmlXPathContextPtr ctxt;
	    xmlXPathObjectPtr res;
	    xmlSecNodeSetType type;

	    ctxt = xmlXPtrNewContext(state->curDoc, 
				    xmlDocGetRootElement(state->curDoc), 
				    NULL);
	    if(ctxt == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlXPtrNewContext",
			    XMLSEC_ERRORS_R_XML_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);	    
	    }
	    
	    /* evaluate expression but skip '#' */
	    if(strncmp(xptr, "#xpointer(", 10) == 0) {
		type = xmlSecNodeSetTree;
		res = xmlXPtrEval(BAD_CAST (xptr + 1), ctxt);
	    } else {
		static char tmpl[] = "xpointer(id(\'%s\'))";
		char* tmp;
		int size;
		
		/* we need to construct new expression */
		size = xmlStrlen(BAD_CAST tmpl) + 
		       xmlStrlen(BAD_CAST xptr) + 2;
		tmp = (char*)xmlMalloc(size * sizeof(char));
		if(tmp == NULL) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				NULL,
				"xmlMalloc",
				XMLSEC_ERRORS_R_MALLOC_FAILED,
				"size=%d", size);
		    xmlXPathFreeContext(ctxt);
		    return(-1);	    
		}
		
		sprintf(tmp, tmpl, xptr + 1);
		type = xmlSecNodeSetTreeWithoutComments;
		res = xmlXPtrEval(BAD_CAST tmp, ctxt);
		xmlFree(tmp);
	    }

	    if(res == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlXPtrEval",
			    XMLSEC_ERRORS_R_XML_FAILED,
			    "xptr=\"%s\"", 
			    xmlSecErrorsSafeString(xptr + 1));
		xmlXPathFreeContext(ctxt);
		return(-1);	    
	    }

	    if((res->nodesetval == NULL) || (res->nodesetval->nodeNr == 0)) {
		/* TODO: make a check in transforms ctx 
		   it is warning, not an error! */
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    NULL,
			    XMLSEC_ERRORS_R_INVALID_NODESET,
			    "empty");
	    }

	    state->curNodeSet = xmlSecNodeSetCreate(state->curDoc, 
					    res->nodesetval,
					    type);
	    if(state->curNodeSet == NULL){
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlSecNodeSetCreate",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "type=%d", type);	    
		xmlXPathFreeObject(res);
		xmlXPathFreeContext(ctxt);
		return(-1);
	    }
	    res->nodesetval = NULL;
	    
	    xmlXPathFreeObject(res);
	    xmlXPathFreeContext(ctxt);
	}
    }

    return(0);
}

/**
 * xmlSecTransformStateDestroyCurrentDoc:
 */
static void 
xmlSecTransformStateDestroyCurrentDoc(xmlSecTransformStatePtr state) {
    xmlSecAssert(state != NULL);

    if((state->curDoc != NULL) && (state->curDoc != state->initDoc)) {
        xmlFreeDoc(state->curDoc);
    }
    if((state->curNodeSet != NULL) && (state->curNodeSet != state->initNodeSet)) {
        xmlSecNodeSetDestroy(state->curNodeSet);
    }
    state->curDoc = NULL;
    state->curNodeSet = NULL;    
}

/**
 * xmlSecTransformCreateXml:
 *
 * Creates XML document from current state:
 *   1) if there is a pending c14n or binary transforms -- apply
 *   2) if curDoc == NULL and initUri != NULL then load uri
 *   3) if curDoc != NULL do nothing (no pending transforms)
 * otherwise initUir and curDoc are both null and it is an error
 */
static int  
xmlSecTransformCreateXml(xmlSecTransformStatePtr state) {
    int ret;

    xmlSecAssert2(state != NULL, -1);
    
    if((state->curDoc == NULL) && (state->initUri == NULL)) { 
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_DATA,
    		    "both doc and uri are null");
        return(-1);
    }

    if((state->curDoc == NULL) && (state->curFirstBinTransform == NULL)) {
	/* load XML document directly from file */
	state->curDoc = xmlSecParseFile(state->initUri);
	if(state->curDoc == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecParseFile",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"uri=\"%s\"", 
			xmlSecErrorsSafeString(state->initUri));
	    return(-1);
	}
	state->curNodeSet = NULL;
    } else if((state->curFirstBinTransform != NULL) || (state->curC14NTransform != NULL)) { 
        /* 
         * bin transforms chain is defined or c14n is pending
         * the source is curDoc 
         */
        ret = xmlSecTransformCreateBin(state);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCreateBin",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	/* parse XML doc from memory */
	state->curDoc = xmlSecParseMemory(xmlSecBufferGetData(state->curBuf), 
		    			  xmlSecBufferGetSize(state->curBuf), 1);
	if(state->curDoc == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecParseMemory",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);	    
	}
	/* do not forget to empty buffer! */
	xmlSecBufferEmpty(state->curBuf);	
    } else {
	/* 
	 * do nothing because curDoc != NULL and there is no pending 
	 * binary or c14n transforms
	 */
    }
    return(0);
}

/**
 * xmlSecTransformCreateBin:
 */
static int 
xmlSecTransformCreateBin(xmlSecTransformStatePtr state) {
    int ret;
    
    xmlSecAssert2(state != NULL, -1);
    
    if(state->curDoc != NULL) {
        ret = xmlSecTransformCreateBinFromXml(state);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCreateBinFromXml",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    } else if(state->initUri != NULL) {
        ret = xmlSecTransformCreateBinFromUri(state);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCreateBinFromUri",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_DATA,
    		    "both doc and uri are null");
	return(-1);
    }
    
    return(0);
}

/**
 * xmlSecTransformCreateBinFromXml:
 */
static int  
xmlSecTransformCreateBinFromXml(xmlSecTransformStatePtr state) {
    xmlSecTransformPtr buffer;
    xmlOutputBufferPtr output;
    int ret;

    xmlSecAssert2(state != NULL, -1);
    xmlSecAssert2(state->curDoc != NULL, -1);
    
    /* first of all, add the memory buffer at the end */
    buffer = xmlSecTransformCreate(xmlSecTransformMemBufId, 0);
    if(buffer == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=\"%s\"",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformMemBufId)));
	return(-1);	
    }
    
    
    if(xmlSecTransformAddAfter(state->curLastBinTransform, buffer) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformAddAfter",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(buffer)));
	xmlSecTransformDestroy(buffer, 1);
	return(-1);
    }
    if(state->curFirstBinTransform == NULL) {
	state->curFirstBinTransform = buffer;
    }
    state->curLastBinTransform = buffer;

    /* now create output buffer for c14n */
    output = xmlOutputBufferCreateIO((xmlOutputWriteCallback)xmlSecTransformWriteBin, 
				  (xmlOutputCloseCallback)xmlSecTransformFlushBin, 
				  (void*)state->curFirstBinTransform, NULL);
    if(output == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlOutputBufferCreateIO",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* 
     * by default (state->c14n == NULL) we use inclusive c14n:
     *
     * If the data object is a node-set and the next transform requires octets, 
     * the signature application MUST attempt to convert the node-set to an octet 
     * stream using Canonical XML [XML-C14N].  
     *
     * the story is different if the first 
     * transform is base64 decode:
     *
     * http://www.w3.org/TR/xmldsig-core/#sec-Base-64
     *
     * This transform requires an octet stream for input. If an XPath node-set 
     * (or sufficiently functional alternative) is given as input, then it is 
     * converted to an octet stream by performing operations logically equivalent 
     * to 1) applying an XPath transform with expression self::text(), then 2) 
     * taking the string-value of the node-set. Thus, if an XML element is 
     * identified by a barename XPointer in the Reference URI, and its content 
     * consists solely of base64 encoded character data, then this transform 
     * automatically strips away the start and end tags of the identified element 
     * and any of its descendant elements as well as any descendant comments and 
     * processing instructions. The output of this transform is an octet stream.
     */
    if((state->curC14NTransform == NULL) && 
	xmlSecTransformCheckId(state->curFirstBinTransform, xmlSecTransformBase64Id)) {
        ret = xmlSecTransformPreBase64Decode(state->curDoc->children, 
					     state->curNodeSet, output);
    } else {
        ret = xmlSecTransformExecuteC14N(state->curC14NTransform, 
			 state->curDoc, state->curNodeSet, output);
        if(state->curC14NTransform != NULL) {
	    xmlSecTransformDestroy(state->curC14NTransform, 0);
	    state->curC14NTransform = NULL;
	}
    }    
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformPreBase64Decode or xmlSecTransformExecuteC14N",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlOutputBufferClose(output);
	return(-1);	
    }

    /* flush data in the buffer by closing it */    
    ret = xmlOutputBufferClose(output);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlOutputBufferClose",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }

    /* "reassign" the buffer */
    if(state->curBuf != NULL) {
	xmlSecBufferDestroy(state->curBuf);
    }
    state->curBuf = xmlSecTransformMemBufGetBuffer(buffer, 1);
        
    /* cleanup */    
    xmlSecTransformDestroyAll(state->curFirstBinTransform);
    state->curFirstBinTransform = state->curLastBinTransform = NULL;
    xmlSecTransformStateDestroyCurrentDoc(state);
    return(0);
}

/**
 * xmlSecTransformCreateBinFromXml:
 */
static int  
xmlSecTransformCreateBinFromUri(xmlSecTransformStatePtr state) {
    xmlSecTransformPtr ptr;
    unsigned char buffer[XMLSEC_TRANSFORM_BUFFER_SIZE];
    int ret;

    xmlSecAssert2(state != NULL, -1);
    xmlSecAssert2(state->initUri != NULL, -1);

    /* add the uri load at the beginning */
    ptr = xmlSecTransformCreate(xmlSecInputUri, 0);
    if(ptr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=\"%s\"",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecInputUri)));
	return(-1);	
    }    
    
    ret = xmlSecInputUriTransformOpen(ptr, state->initUri);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecInputUriTransformOpen",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "uri=\"%s\"",
		    xmlSecErrorsSafeString(state->initUri));
	xmlSecTransformDestroy(ptr, 1);
	return(-1);	
    }
    
    if(xmlSecTransformAddBefore(state->curFirstBinTransform, ptr) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformAddBefore",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=\"%s\"",		    
		    xmlSecErrorsSafeString(xmlSecTransformGetName(ptr)));
	xmlSecTransformDestroy(ptr, 1);
	return(-1);
    }
    if(state->curLastBinTransform == NULL) state->curLastBinTransform = ptr;
    state->curFirstBinTransform = ptr;
	
    /* empty the current buffer */
    xmlSecBufferEmpty(state->curBuf);
    
    do {
	ret = xmlSecTransformReadBin(state->curLastBinTransform, buffer, XMLSEC_TRANSFORM_BUFFER_SIZE);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformReadBin",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformGetName(state->curLastBinTransform)));
	    return(-1);
	} else if(ret > 0) {
	    xmlSecBufferAppend(state->curBuf, buffer, ret);
	}
    } while(ret > 0);

    /* cleanup */
    xmlSecTransformDestroyAll(state->curFirstBinTransform);
    state->curFirstBinTransform = state->curLastBinTransform = NULL;
    
    return(0);
}

/**
 * xmlSecTransformPreBase64Decode:
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-Base-64:
 *
 * Base64 transform
 * This transform requires an octet stream for input. If an XPath node-set 
 * (or sufficiently functional alternative) is given as input, then it is 
 * converted to an octet stream by performing operations logically equivalent 
 * to 1) applying an XPath transform with expression self::text(), then 2) 
 * taking the string-value of the node-set. Thus, if an XML element is 
 * identified by a barename XPointer in the Reference URI, and its content 
 * consists solely of base64 encoded character data, then this transform 
 * automatically strips away the start and end tags of the identified element 
 * and any of its descendant elements as well as any descendant comments and 
 * processing instructions. The output of this transform is an octet stream.
 *
 */
static int
xmlSecTransformPreBase64DecodeWalk(xmlSecNodeSetPtr nodeSet, xmlNodePtr cur, 
				   xmlNodePtr parent ATTRIBUTE_UNUSED, 
				   void* data) {
    xmlSecAssert2(nodeSet != NULL, -1);
    xmlSecAssert2(cur != NULL, -1);
    xmlSecAssert2(data != NULL, -1);

    if(cur->type == XML_TEXT_NODE) {
	xmlOutputBufferWriteString((xmlOutputBufferPtr)data, 
				    (char*)(cur->content)); 
    }
    return(0);
}

static int 
xmlSecTransformPreBase64Decode(const xmlNodePtr node, xmlSecNodeSetPtr nodeSet, 
			       xmlOutputBufferPtr output) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(output != NULL, -1);

    if(nodeSet != NULL) {
	if(xmlSecNodeSetWalk(nodeSet, xmlSecTransformPreBase64DecodeWalk, output) < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecNodeSetWalk",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformPreBase64DecodeWalk");
	    return(-1);
	}
    } else if(node->type == XML_ELEMENT_NODE) {
	cur = node->children;
	while(cur != NULL) {
	    ret = xmlSecTransformPreBase64Decode(cur, NULL, output);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlSecTransformPreBase64Decode",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	}
    } else if(node->type == XML_TEXT_NODE) { 
        xmlOutputBufferWriteString(output, (char*)node->content); 	
    }
    return(0);
}

int
xmlSecTransformStateFinalToNode(xmlSecTransformStatePtr state, xmlNodePtr node, 
				int addBase64, xmlSecTransformCtxPtr transformCtx) {
    int ret;
    
    xmlSecAssert2(state != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);
        
    if(addBase64) {
	xmlSecTransformPtr base64;
	
	base64 = xmlSecTransformCreate(xmlSecTransformBase64Id, 0);
	if(base64 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformBase64Id)));
	    return(-1);
	}
	base64->encode = 1;
	
	ret = xmlSecTransformStateUpdate(state, base64);
	if(ret < 0) {    
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformStateUpdate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformGetName(base64)));
	    xmlSecTransformDestroy(base64, 1); 
	    return(-1);
	}
    }
    
    ret = xmlSecTransformStateFinal(state, xmlSecTransformResultBinary);
    if((ret < 0) || (state->curBuf == NULL)) {
    	xmlSecError(XMLSEC_ERRORS_HERE,	
		    NULL,
		    "xmlSecTransformStateFinal",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformResultBinary");
	return(-1);
    }

    /* just in case */
    xmlSecBufferAppend(state->curBuf, (unsigned char*)"\0", 1);

    xmlNodeSetContent(node, xmlSecBufferGetData(state->curBuf));
    return(0);
}

int
xmlSecTransformStateFinalVerifyNode(xmlSecTransformStatePtr state, 
				    xmlSecTransformPtr transform,
				    xmlNodePtr node, 
				    xmlSecTransformCtxPtr transformCtx) {
    xmlChar* nodeContent;
    size_t nodeContentSize;
    int ret;
    
    xmlSecAssert2(state != NULL, -1);
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    
    ret = xmlSecTransformStateFinal(state, xmlSecTransformResultBinary);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformStateFinal",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformResultBinary");
	return(-1);
    }

    nodeContent = xmlNodeGetContent(node);
    if(nodeContent == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNodeGetContent",
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeGetName(node)));
	return(-1);
    }
    
    /* 
     * small trick: decode in the same buffer becasue base64 decode result 
     * buffer size is always less than input buffer size
     */
    ret = xmlSecBase64Decode(nodeContent, (unsigned char *)nodeContent, 
			     xmlStrlen(nodeContent) + 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBase64Decode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFree(nodeContent);
	return(-1);
    }
    nodeContentSize = ret;
     
    ret = xmlSecTransformVerify(transform, nodeContent, nodeContentSize, transformCtx);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformVerify",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)));
	xmlFree(nodeContent);
	return(-1);
    }
    
    xmlFree(nodeContent);
    return(0);
}

