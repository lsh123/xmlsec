/** 
 * XMLSec library
 *
 * List
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
 
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/list.h>
#include <xmlsec/errors.h>


static int		xmlSecPtrListEnsureSize			(xmlSecPtrListPtr list,
								 size_t size);
								 
static xmlSecAllocMode gAllocMode = xmlSecAllocModeDouble;
static size_t gInitialSize = 64;

void 
xmlSecPtrListSetDefaultAllocMode(xmlSecAllocMode defAllocMode, size_t defInitialSize) {
    xmlSecAssert(defInitialSize > 0);
    
    gAllocMode = defAllocMode;
    gInitialSize = defInitialSize;
}

xmlSecPtrListPtr 
xmlSecPtrListCreate(xmlSecPtrListId id) {
    xmlSecPtrListPtr list;
    int ret;
    
    xmlSecAssert2(id != xmlSecPtrListIdUnknown, NULL);
    
    /* Allocate a new xmlSecPtrList and fill the fields. */
    list = (xmlSecPtrListPtr)xmlMalloc(sizeof(xmlSecPtrList));
    if(list == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecPtrListKlassGetName(id)),
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecPtrList)=%d", 
		    sizeof(xmlSecPtrList));
	return(NULL);
    }
    
    ret = xmlSecPtrListInitialize(list, id);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(id->name),
		    "xmlSecPtrListInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFree(list);
	return(NULL);
    }
    
    return(list);    
}

void 
xmlSecPtrListDestroy(xmlSecPtrListPtr list) {
    xmlSecAssert(xmlSecPtrListIsValid(list));
    xmlSecPtrListFinalize(list);
    xmlFree(list);
}

int 
xmlSecPtrListInitialize(xmlSecPtrListPtr list, xmlSecPtrListId id) {
    xmlSecAssert2(id != xmlSecPtrListIdUnknown, -1);
    xmlSecAssert2(list != NULL, -1);

    memset(list, 0, sizeof(xmlSecPtrList));    
    list->id = id;
    list->allocMode = gAllocMode;
    
    return(0);
}

void
xmlSecPtrListFinalize(xmlSecPtrListPtr list) {
    xmlSecAssert(xmlSecPtrListIsValid(list));

    if(list->id->destroyItem != NULL) {
	size_t pos;
	
	for(pos = 0; pos < list->use; ++pos) {
	    xmlSecAssert(list->data != NULL);
	    if(list->data[pos] != NULL) {
		list->id->destroyItem(list->data[pos]);
	    }
	}
    }
    if(list->max > 0) {
	xmlSecAssert(list->data != NULL);

	memset(list->data, 0, sizeof(xmlSecPtr) * list->use);
	xmlFree(list->data);
    }
    memset(list, 0, sizeof(xmlSecPtrList));    
}

int
xmlSecPtrListCopy(xmlSecPtrListPtr dst, xmlSecPtrListPtr src) {
    size_t i;
    int ret;
    
    xmlSecAssert2(xmlSecPtrListIsValid(dst), -1);
    xmlSecAssert2(xmlSecPtrListIsValid(src), -1);
    xmlSecAssert2(dst->id == src->id, -1);
    
    /* allocate memory */
    ret = xmlSecPtrListEnsureSize(dst, dst->use + src->use);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecPtrListGetName(src)),
		    "xmlSecPtrListEnsureSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%d", src->use);
	return(-1);
    }

    /* copy one item after another */    
    for(i = 0; i < src->use; ++i, ++dst->use) {
	xmlSecAssert2(src->data != NULL, -1);
	xmlSecAssert2(dst->data != NULL, -1);
	
	if((dst->id->duplicateItem != NULL) && (src->data[i] != NULL)) {
	    dst->data[dst->use] = dst->id->duplicateItem(src->data[i]);
	    if(dst->data[dst->use] == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecPtrListGetName(src)),
			    "duplicateItem",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	} else {
	    dst->data[dst->use] = src->data[i];
	}
    }
    
    return(0);
}

xmlSecPtrListPtr 
xmlSecPtrListDuplicate(xmlSecPtrListPtr list) {
    xmlSecPtrListPtr newList;
    int ret;
    
    xmlSecAssert2(xmlSecPtrListIsValid(list), NULL);
    
    newList = xmlSecPtrListCreate(list->id);
    if(newList == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecPtrListGetName(list)),
		    "xmlSecPtrListCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }
    
    ret = xmlSecPtrListCopy(newList, list);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecPtrListGetName(list)),
		    "xmlSecPtrListCopy",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecPtrListDestroy(newList);
	return(NULL);
    }
    return(newList);
}

size_t	
xmlSecPtrListGetSize(xmlSecPtrListPtr list) {
    xmlSecAssert2(xmlSecPtrListIsValid(list), 0);
    
    return(list->use);
}

xmlSecPtr 
xmlSecPtrListGetItem(xmlSecPtrListPtr list, size_t pos) {
    xmlSecAssert2(xmlSecPtrListIsValid(list), NULL);
    xmlSecAssert2(list->data != NULL, NULL);
    xmlSecAssert2(pos < list->use, NULL);

    return(list->data[pos]);
}

int 
xmlSecPtrListAdd(xmlSecPtrListPtr list, xmlSecPtr item) {
    int ret;
    
    xmlSecAssert2(xmlSecPtrListIsValid(list), -1);
    
    ret = xmlSecPtrListEnsureSize(list, list->use + 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecPtrListGetName(list)),
		    "xmlSecPtrListAdd",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%d", list->use + 1);
	return(-1);
    }
    
    list->data[list->use++] = item;
    return(0);
}

int 
xmlSecPtrListSet(xmlSecPtrListPtr list, xmlSecPtr item, size_t pos) {
    xmlSecAssert2(xmlSecPtrListIsValid(list), -1);
    xmlSecAssert2(list->data != NULL, -1);
    xmlSecAssert2(pos < list->use, -1);

    if((list->id->destroyItem != NULL) && (list->data[pos] != NULL)) {
	list->id->destroyItem(list->data[pos]);
    }
    list->data[pos] = item;
    return(0);
}

int 
xmlSecPtrListRemove(xmlSecPtrListPtr list, size_t pos) {
    xmlSecAssert2(xmlSecPtrListIsValid(list), -1);
    xmlSecAssert2(list->data != NULL, -1);
    xmlSecAssert2(pos < list->use, -1);

    if((list->id->destroyItem != NULL) && (list->data[pos] != NULL)) {
	list->id->destroyItem(list->data[pos]);
    }
    list->data[pos] = NULL;
    if(pos == list->use - 1) {
	--list->use;
    }
    return(0);
}

void 
xmlSecPtrListDebugDump(xmlSecPtrListPtr list, FILE* output) {
    xmlSecAssert(xmlSecPtrListIsValid(list));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== list size: %d\n", list->use);    
    if(list->id->debugDumpItem != NULL) {
	size_t pos;
	
	for(pos = 0; pos < list->use; ++pos) {
	    xmlSecAssert(list->data != NULL);
	    if(list->data[pos] != NULL) {
		list->id->debugDumpItem(list->data[pos], output);
	    }
	}	
    }
}

void 
xmlSecPtrListDebugXmlDump(xmlSecPtrListPtr list, FILE* output) {
    xmlSecAssert(xmlSecPtrListIsValid(list));
    xmlSecAssert(output != NULL);
    
    fprintf(output, "<List size=\"%d\">\n", list->use);    
    if(list->id->debugXmlDumpItem != NULL) {
	size_t pos;
	
	for(pos = 0; pos < list->use; ++pos) {
	    xmlSecAssert(list->data != NULL);
	    if(list->data[pos] != NULL) {
		list->id->debugXmlDumpItem(list->data[pos], output);
	    }
	}	
    }
    fprintf(output, "</List>\n");    
}

static int 
xmlSecPtrListEnsureSize(xmlSecPtrListPtr list, size_t size) {
    xmlSecPtr* newData;
    size_t newSize = 0;

    xmlSecAssert2(xmlSecPtrListIsValid(list), -1);
    
    if(size < list->max) {
	return(0);
    }

    switch(list->allocMode) {
	case xmlSecAllocModeExact:
	    newSize = size + 8;
	    break;
	case xmlSecAllocModeDouble:
	    newSize = 2 * size + 32;
	    break;
    }
    
    if(newSize < gInitialSize) {
	newSize = gInitialSize;
    }
    
    newData = (xmlSecPtr*)xmlRealloc(list->data, sizeof(xmlSecPtr) * newSize);
    if(newData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecPtrListGetName(list)),
		    "xmlRealloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecPtr)*%d=%d", 
		    newSize, sizeof(xmlSecPtr) * newSize);
	return(-1);
    }
    
    list->data = newData;
    list->max = newSize;
    
    return(0);
}

/***********************************************************************
 *
 * Static Objects list
 *
 **********************************************************************/
static xmlSecPtrListKlass xmlSecStaticObjectListKlass = {
    BAD_CAST "static-objects-list",
    NULL,					/* xmlSecPtrDuplicateItemMethod duplicateItem; */
    NULL,					/* xmlSecPtrDestroyItemMethod destroyItem; */
    NULL,					/* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    NULL,					/* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

xmlSecPtrListId 
xmlSecStaticObjectListGetKlass(void) {
    return(&xmlSecStaticObjectListKlass);
}

/***********************************************************************
 *
 * strings list
 *
 **********************************************************************/
static xmlSecPtr 	xmlSecStringListDuplicateItem		(xmlSecPtr ptr);
static void		xmlSecStringListDestroyItem		(xmlSecPtr ptr);

static xmlSecPtrListKlass xmlSecStringListKlass = {
    BAD_CAST "strings-list",
    xmlSecStringListDuplicateItem,		/* xmlSecPtrDuplicateItemMethod duplicateItem; */
    xmlSecStringListDestroyItem,		/* xmlSecPtrDestroyItemMethod destroyItem; */
    NULL,					/* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    NULL,					/* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

xmlSecPtrListId 
xmlSecStringListGetKlass(void) {
    return(&xmlSecStringListKlass);
}

static xmlSecPtr 
xmlSecStringListDuplicateItem(xmlSecPtr ptr) {
    xmlSecAssert2(ptr != NULL, NULL);
    
    return(xmlStrdup((xmlChar*)ptr));
}

static void 
xmlSecStringListDestroyItem(xmlSecPtr ptr) {
    xmlSecAssert(ptr != NULL);
    
    xmlFree(ptr);
}


