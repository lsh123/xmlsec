/**		
 * XMLSec library
 *
 * Serializable Objects
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/map.h>
#include <xmlsec/errors.h>

static void		xmlSecObjMapKlassInit			(xmlSecObjKlassPtr klass);
static int		xmlSecObjMapConstructor			(xmlSecObjKlassPtr klass, 
							    	 xmlSecObjPtr obj);
static int		xmlSecObjMapDuplicator			(xmlSecObjKlassPtr klass, 
								 xmlSecObjPtr dst, 
							         xmlSecObjPtr src);
static void		xmlSecObjMapDestructor			(xmlSecObjKlassPtr klass, 
								 xmlSecObjPtr dst);
static void		xmlSecObjMapDebugDump			(xmlSecObjPtr obj,
								 FILE* output,
								 size_t level);
static void		xmlSecObjMapDebugXmlDump		(xmlSecObjPtr obj,
								 FILE* output,
								 size_t level);
static int		xmlSecObjMapFindItem			(xmlSecObjMapPtr map,
								const xmlChar* name);
static int		xmlSecObjMapReallocate			(xmlSecObjMapPtr map,
								size_t delta);

struct _xmlSecObjMapItem {
    xmlChar* 			name;
    xmlSecObjPtr		data;
};

/*********************************************************************
 *
 * Binary Map
 *
 *********************************************************************/
xmlSecObjKlassPtr
xmlSecObjMapKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecObjMapKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecObjMapKlass),
	    "xmlSecObjMap",
	    xmlSecObjMapKlassInit,  /* xmlSecObjKlassInitMethod */
	    NULL,			 /* xmlSecObjKlassFinalizeMethod */
	    
	    /* obj info */
	    sizeof(xmlSecObjMap),
	    xmlSecObjMapConstructor,/* xmlSecObjKlassConstructorMethod */
	    xmlSecObjMapDuplicator, /* xmlSecObjKlassDuplicatorMethod */
	    xmlSecObjMapDestructor, /* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
				       &kklassInfo, xmlSecObjKlassId); 
    } 
    return(klass);   
}


xmlSecObjPtr
xmlSecObjMapGet(xmlSecObjMapPtr map, const xmlChar* name) {
    int i;
        
    xmlSecAssert2(map != NULL, NULL);
    xmlSecAssert2(name != NULL, NULL);

    i = xmlSecObjMapFindItem(map, name);
    if(i < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "item \"%s\" not found", name);
	return(NULL);
    }

    xmlSecAssert2(map->data != NULL, NULL);
    return(map->data[i].data);
}

int
xmlSecObjMapSet(xmlSecObjMapPtr map, const xmlChar* name, xmlSecObjPtr data) {
    int ret;
    
    xmlSecAssert2(map != NULL, -1);
    xmlSecAssert2(name != NULL, -1);

    /* check if we already have such name */
    ret = xmlSecObjMapFindItem(map, name);
    if(ret >= 0) {
	xmlSecAssert2(map->data != NULL, -1);
        if(map->data[ret].data != NULL) {
	    xmlSecObjDelete(map->data[ret].data);
	}
	map->data[ret].data = data;
	return(0);
    }
    
    ret = xmlSecObjMapReallocate(map, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecObjMapReallocate(delta=%d)", 1);
	return(-1);			
    }
    xmlSecAssert2(map->data != NULL, -1);
    xmlSecAssert2(map->maxSize >= map->size + 1, -1);
    
    map->data[map->size].name = xmlStrdup(name);
    map->data[map->size].data = data;
    ++map->size;
    return(0);    
}

void
xmlSecObjMapRemove(xmlSecObjMapPtr map, const xmlChar* name) {
    int i;
    
    xmlSecAssert(map != NULL);
    xmlSecAssert(name != NULL);
    
    i = xmlSecObjMapFindItem(map, name);
    if(i < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "item \"%s\" not found", name);
	return;
    }

    xmlSecAssert(map->data != NULL);

    if(map->data[i].name != NULL) {
	xmlFree(map->data[i].name);
    }
    if(map->data[i].data != NULL) {
	xmlSecObjDelete(map->data[i].data);
    }
    
    if(i + 1 < (int)map->size) {
	memmove(&(map->data[i]), &(map->data[i + 1]), 
		sizeof(xmlSecObjMapItem) * (map->size - i - 1));
    }
    map->data[map->size].name = NULL;
    map->data[map->size].data = NULL;
    --map->size;
}

void
xmlSecObjMapEmpty(xmlSecObjMapPtr map) {
    size_t i;
    
    xmlSecAssert(map != NULL);

    for(i = 0; i < map->size; ++i) {
	xmlSecAssert(map->data != NULL);
	xmlSecAssert(map->data[i].name != NULL);

	if(map->data[i].name != NULL) {
	    xmlFree(map->data[i].name);
	}
        if(map->data[i].data != NULL) {
	    xmlSecObjDelete(map->data[i].data);
	}
    }
    if(map->maxSize > 0) {
	xmlSecAssert(map->data != NULL);
	memset(map->data, 0, map->maxSize * sizeof(xmlSecObjMapItem));
    }
    map->size = 0;
}

size_t
xmlSecObjMapGetSize(xmlSecObjMapPtr map) {
    xmlSecAssert2(map != NULL, 0);
    
    return(map->size);
}

xmlSecObjPtr
xmlSecObjMapGetData(xmlSecObjMapPtr map, size_t pos) {
    xmlSecAssert2(map != NULL, NULL);

    if(pos < map->size) {
	xmlSecAssert2(map->data != NULL, NULL);

	return (map->data[pos].data);
    }
    return(NULL);
}

const xmlChar*
xmlSecObjMapGetName(xmlSecObjMapPtr map, size_t pos) {
    xmlSecAssert2(map != NULL, NULL);

    if(pos < map->size) {
	xmlSecAssert2(map->data != NULL, NULL);

	return (map->data[pos].name);
    }
    return(NULL);
}

static void
xmlSecObjMapKlassInit(xmlSecObjKlassPtr klass) {
    klass->debugDump 		= xmlSecObjMapDebugDump;
    klass->debugXmlDump 	= xmlSecObjMapDebugXmlDump;
}

static int
xmlSecObjMapConstructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr obj) {
    xmlSecObjMapPtr map = xmlSecObjMapCast(obj);

    xmlSecAssert2(map != NULL, -1);

    map->data 	= NULL;
    map->size	= 0;
    map->maxSize= 0;
    
    return(0);
}

static int
xmlSecObjMapDuplicator(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr dst, xmlSecObjPtr src) {
    xmlSecObjMapPtr mapDst = xmlSecObjMapCast(dst);
    xmlSecObjMapPtr mapSrc = xmlSecObjMapCast(src);
    size_t i;
    int ret;
        
    xmlSecAssert2(mapDst != NULL, -1);
    xmlSecAssert2(mapSrc != NULL, -1);

    xmlSecObjMapEmpty(mapDst);

    ret = xmlSecObjMapReallocate(mapDst, mapSrc->size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecObjMapReallocate(delta=%d)", mapSrc->size);
	return(-1);			
    }
    xmlSecAssert2(mapDst->data != NULL, -1);
    xmlSecAssert2(mapDst->maxSize >= mapSrc->size, -1);
    
    for(i = 0; i < mapSrc->size; ++i) {
	mapDst->data[i].name = xmlStrdup(mapSrc->data[i].name);
	mapDst->data[i].data = xmlSecObjDuplicate(mapSrc->data[i].data);
    }    
    mapDst->size = mapSrc->size;
    return(0);
}

static void
xmlSecObjMapDestructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
				    xmlSecObjPtr obj) {
    xmlSecObjMapPtr map = xmlSecObjMapCast(obj);

    xmlSecAssert(map != NULL);

    xmlSecObjMapEmpty(map);
    if(map->data != NULL) {
	xmlFree(map->data);
    }
    map->data   = NULL;
    map->size	 = 0;
    map->maxSize= 0;
}

static void
xmlSecObjMapDebugDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecObjMapPtr map = xmlSecObjMapCast(obj);

    xmlSecAssert(map != NULL);
    xmlSecAssert(output != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "map size: %d\n", map->size);
}

static void
xmlSecObjMapDebugXmlDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecObjMapPtr map = xmlSecObjMapCast(obj);
	    
    xmlSecAssert(map != NULL);
    xmlSecAssert(output != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "<Map size=\"%d\"/>\n", map->size);
}

static int
xmlSecObjMapFindItem(xmlSecObjMapPtr map, const xmlChar* name) {
    size_t i;
    
    xmlSecAssert2(map != NULL, -1);
    xmlSecAssert2(name != NULL, -1);

    for(i = 0; i < map->size; ++i) {
	xmlSecAssert2(map->data != NULL, -1);
	xmlSecAssert2(map->data[i].name != NULL, -1);

	if(xmlStrEqual(map->data[i].name, name)) {
	    return(i);
	}
    }
    return(-1);
}

static int
xmlSecObjMapReallocate(xmlSecObjMapPtr map, size_t delta) {
    xmlSecObjMapItem* p;
    size_t size;
    
    xmlSecAssert2(map != NULL, -1);
    
    if(map->size + delta < map->maxSize) {
	return(0);
    }
    
    size = 4 * (map->size + delta) / 3 + 1;
    p = (xmlSecObjMapItem*)xmlRealloc(map->data, size * sizeof(xmlSecObjMapItem));
    if(p == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_MALLOC_FAILED,	
		    "%d", size);
	return(-1);			
    }
    
    map->data = p;
    map->maxSize = size;
    return(0);	
}

