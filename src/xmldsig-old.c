	4    /* next node is required SignatureValue */
/**
 * xmlSecSignedInfoCalculate:
 *
 */


static int
xmlSecObjectRead(xmlNodePtr objectNode, int sign, xmlSecDSigResultPtr result) {
    xmlNodePtr cur;
    int ret;
    
    xmlSecAssert2(result != NULL, -1);
    xmlSecAssert2(result->ctx != NULL, -1);
    xmlSecAssert2(objectNode != NULL, -1);
    

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


}


