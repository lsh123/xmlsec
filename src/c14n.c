/** 
 * XMLSec library
 *
 * C14N transforms
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/c14n.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/list.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/errors.h>

/******************************************************************************
 *
 * C14N transforms
 *
 * Inclusive namespaces list for ExclC14N (xmlSecStringList) is located 
 * after xmlSecTransform structure
 * 
 *****************************************************************************/
#define xmlSecTransformC14NSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecPtrList))
#define xmlSecTransformC14NGetNsList(transform) \
    ((xmlSecTransformCheckSize((transform), xmlSecTransformC14NSize)) ? \
	(xmlSecPtrListPtr)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)) : \
	(xmlSecPtrListPtr)NULL)

#define xmlSecTransformC14NCheckId(transform) \
    (xmlSecTransformInclC14NCheckId((transform)) || \
     xmlSecTransformExclC14NCheckId((transform)) )
#define xmlSecTransformInclC14NCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecTransformInclC14NId) || \
     xmlSecTransformCheckId((transform), xmlSecTransformInclC14NWithCommentsId))
#define xmlSecTransformExclC14NCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecTransformExclC14NId) || \
     xmlSecTransformCheckId((transform), xmlSecTransformExclC14NWithCommentsId) )


static int		xmlSecTransformC14NInitialize	(xmlSecTransformPtr transform);
static void		xmlSecTransformC14NFinalize	(xmlSecTransformPtr transform);
static int 		xmlSecTransformC14NReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr node);
static int 		xmlSecTransformC14NExec		(xmlSecTransformPtr transform,
							 xmlDocPtr doc,
							 xmlSecNodeSetPtr nodes,
							 xmlOutputBufferPtr buffer);
static int
xmlSecTransformC14NInitialize(xmlSecTransformPtr transform) {
    xmlSecPtrListPtr nsList;
    int ret;
    
    xmlSecAssert2(xmlSecTransformC14NCheckId(transform), -1);

    nsList = xmlSecTransformC14NGetNsList(transform);
    xmlSecAssert2(nsList != NULL, -1);
    
    ret = xmlSecPtrListInitialize(nsList, xmlSecStringListId);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecPtrListInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

static void
xmlSecTransformC14NFinalize(xmlSecTransformPtr transform) {
    xmlSecPtrListPtr nsList;

    xmlSecAssert(xmlSecTransformC14NCheckId(transform));

    nsList = xmlSecTransformC14NGetNsList(transform);
    xmlSecAssert(xmlSecPtrListCheckId(nsList, xmlSecStringListId));
    
    xmlSecPtrListFinalize(nsList);
}

static int
xmlSecTransformC14NReadNode(xmlSecTransformPtr transform, xmlNodePtr node) {
    xmlSecPtrListPtr nsList;
    xmlNodePtr cur;
    xmlChar *list;
    xmlChar *p, *n, *tmp;
    int ret;
    
    /* we have something to read only for exclusive c14n transforms */
    xmlSecAssert2(xmlSecTransformExclC14NCheckId(transform), -1);
    xmlSecAssert2(node != NULL, -1);
        
    nsList = xmlSecTransformC14NGetNsList(transform);
    xmlSecAssert2(xmlSecPtrListCheckId(nsList, xmlSecStringListId), -1);
    xmlSecAssert2(xmlSecPtrListGetSize(nsList) == 0, -1);
    
    /* there is only one optional node */
    cur = xmlSecGetNextElementNode(node->children);  
    if(cur != NULL) {
	if(!xmlSecCheckNodeName(cur, xmlSecNodeInclusiveNamespaces, xmlSecNsExcC14N)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        NULL,
			xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
			XMLSEC_ERRORS_R_INVALID_NODE,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeInclusiveNamespaces));
	    return(-1);
	}
    
        list = xmlGetProp(cur, xmlSecAttrPrefixList);
	if(list == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			xmlSecErrorsSafeString(xmlSecAttrPrefixList),
			XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(cur)));
	    return(-1);
	}
    
        /* the list of namespaces is space separated */
	for(p = n = list; ((p != NULL) && ((*p) != '\0')); p = n) {
	    n = (xmlChar*)strchr(p, ' ');
	    if(n != NULL) {
	        *(n++) = '\0';
	    }	
	
	    tmp = xmlStrdup(p);
	    if(tmp == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
		    	    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlStrdup",
		    	    XMLSEC_ERRORS_R_MALLOC_FAILED,
			    "len=%d", xmlStrlen(p));
		xmlFree(list);
		return(-1);	
	    }
	
	    ret = xmlSecPtrListAdd(nsList, tmp);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecPtrListAdd",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
	        xmlFree(tmp);
		xmlFree(list);
	        return(-1);
	    }
	}
        xmlFree(list);

	/* add NULL at the end */
        ret = xmlSecPtrListAdd(nsList, NULL);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		        "xmlSecPtrListAdd",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
		        XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}

	cur = xmlSecGetNextElementNode(cur->next);        
    }
    
    /* check that we have nothing else */
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
xmlSecTransformC14NExec(xmlSecTransformPtr transform, xmlDocPtr doc,
			xmlSecNodeSetPtr nodes, xmlOutputBufferPtr buffer) {
    xmlSecPtrListPtr nsList;
    int ret;


    xmlSecAssert2(doc!= NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);

    if(transform == NULL) {
	/* the default c14n transform */
	ret = xmlC14NExecute(doc, 
			(xmlC14NIsVisibleCallback)xmlSecNodeSetContains, 
			nodes, 
			0, NULL, 0, buffer);
    } else if(xmlSecTransformCheckId(transform, xmlSecTransformInclC14NId)) {    
    	ret = xmlC14NExecute(doc, 
			(xmlC14NIsVisibleCallback)xmlSecNodeSetContains, 
			nodes, 
			0, NULL, 0, buffer);
    } else if(xmlSecTransformCheckId(transform, xmlSecTransformInclC14NWithCommentsId)) {
	 ret = xmlC14NExecute(doc, 
			(xmlC14NIsVisibleCallback)xmlSecNodeSetContains, 
			nodes, 
			0, NULL, 1, buffer); 
    } else if(xmlSecTransformCheckId(transform, xmlSecTransformExclC14NId)) {
	/* we are using a semi-hack here: we know that xmlSecPtrList keeps
	   all pointers in the big array */
	nsList = xmlSecTransformC14NGetNsList(transform);
	xmlSecAssert2(xmlSecPtrListCheckId(nsList, xmlSecStringListId), -1);
	
	ret = xmlC14NExecute(doc, 
			(xmlC14NIsVisibleCallback)xmlSecNodeSetContains, 
			nodes, 
			1, (xmlChar**)(nsList->data), 0, buffer);
    } else if(xmlSecTransformCheckId(transform, xmlSecTransformExclC14NWithCommentsId)) {
	/* we are using a semi-hack here: we know that xmlSecPtrList keeps
	   all pointers in the big array */
	nsList = xmlSecTransformC14NGetNsList(transform);
	xmlSecAssert2(xmlSecPtrListCheckId(nsList, xmlSecStringListId), -1);
	
	ret = xmlC14NExecute(doc, 
			(xmlC14NIsVisibleCallback)xmlSecNodeSetContains, 
			nodes, 
			1, (xmlChar**)(nsList->data), 1, buffer);
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlC14NExecute",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    
    return(0);
}

static xmlSecTransformKlass xmlSecTransformInclC14NKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    xmlSecTransformC14NSize,		/* size_t objSize */

    xmlSecNameC14N,
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecTransformUsageC14NMethod | xmlSecTransformUsageDSigTransform,		/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefC14N, 			/* const xmlChar href; */

    xmlSecTransformC14NInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformC14NFinalize,	/* xmlSecTransformFinalizeMethod finalize; */
    NULL,				/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,	/* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,				/* xmlSecTransformPushBinMethod pushBin; */
    NULL,				/* xmlSecTransformPopBinMethod popBin; */
    NULL,				/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,				/* xmlSecTransformPopXmlMethod popXml; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */

    NULL,				/* xmlSecTransformExecuteXmlMethod executeXml; */
    xmlSecTransformC14NExec		/* xmlSecTransformC14NExecuteMethod executeC14N; */
};

xmlSecTransformId 
xmlSecTransformInclC14NGetKlass(void) {
    return(&xmlSecTransformInclC14NKlass);
}
 
static xmlSecTransformKlass xmlSecTransformInclC14NWithCommentsKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    xmlSecTransformC14NSize,		/* size_t objSize */

    /* same as xmlSecTransformId */    
    xmlSecNameC14NWithComments,
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecTransformUsageC14NMethod | xmlSecTransformUsageDSigTransform,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefC14NWithComments, 	/* const xmlChar href; */

    xmlSecTransformC14NInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformC14NFinalize,	/* xmlSecTransformFinalizeMethod finalize; */
    NULL,				/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,	/* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,				/* xmlSecTransformPushBinMethod pushBin; */
    NULL,				/* xmlSecTransformPopBinMethod popBin; */
    NULL,				/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,				/* xmlSecTransformPopXmlMethod popXml; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */

    NULL,				/* xmlSecTransformExecuteXmlMethod executeXml; */
    xmlSecTransformC14NExec		/* xmlSecTransformC14NExecuteMethod executeC14N; */
};

xmlSecTransformId 
xmlSecTransformInclC14NWithCommentsGetKlass(void) {
    return(&xmlSecTransformInclC14NWithCommentsKlass);
}

static xmlSecTransformKlass xmlSecTransformExclC14NKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    xmlSecTransformC14NSize,		/* size_t objSize */

    xmlSecNameExcC14N,			/* const xmlChar* name; */
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecTransformUsageC14NMethod | xmlSecTransformUsageDSigTransform,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefExcC14N,			/* const xmlChar href; */

    xmlSecTransformC14NInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformC14NFinalize,	/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecTransformC14NReadNode,	/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,	/* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,				/* xmlSecTransformPushBinMethod pushBin; */
    NULL,				/* xmlSecTransformPopBinMethod popBin; */
    NULL,				/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,				/* xmlSecTransformPopXmlMethod popXml; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
    NULL,				/* xmlSecTransformExecuteXmlMethod executeXml; */
    xmlSecTransformC14NExec		/* xmlSecTransformC14NExecuteMethod executeC14N; */
};

xmlSecTransformId 
xmlSecTransformExclC14NGetKlass(void) {
    return(&xmlSecTransformExclC14NKlass);
}

static xmlSecTransformKlass xmlSecTransformExclC14NWithCommentsKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    xmlSecTransformC14NSize,		/* size_t objSize */

    xmlSecNameExcC14NWithComments,
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecTransformUsageC14NMethod | xmlSecTransformUsageDSigTransform,		/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefExcC14NWithComments,	/* const xmlChar href; */

    xmlSecTransformC14NInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformC14NFinalize,	/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecTransformC14NReadNode,	/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,	/* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,				/* xmlSecTransformPushBinMethod pushBin; */
    NULL,				/* xmlSecTransformPopBinMethod popBin; */
    NULL,				/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,				/* xmlSecTransformPopXmlMethod popXml; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */

    NULL,				/* xmlSecTransformExecuteXmlMethod executeXml; */
    xmlSecTransformC14NExec		/* xmlSecTransformC14NExecuteMethod executeC14N; */
};

xmlSecTransformId 
xmlSecTransformExclC14NWithCommentsGetKlass(void) {
    return(&xmlSecTransformExclC14NWithCommentsKlass);
}


