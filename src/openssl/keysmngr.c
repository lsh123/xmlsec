/** 
 * XMLSec library
 *
 * OpenSSL Keys Manager
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
#include <libxml/parser.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/crypto.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/errors.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/openssl/keysmngr.h>


static void		xmlSecOpenSSLKeysMngrKlassInit		(xmlSecObjKlassPtr klass);
static int		xmlSecOpenSSLKeysMngrConstructor	(xmlSecObjKlassPtr klass, 
								 xmlSecObjPtr obj);
static int		xmlSecOpenSSLKeysMngrDuplicator		(xmlSecObjKlassPtr klass, 
							         xmlSecObjPtr dst, 
								 xmlSecObjPtr src);
static void		xmlSecOpenSSLKeysMngrDestructor		(xmlSecObjKlassPtr klass, 
								 xmlSecObjPtr dst);
static void		xmlSecOpenSSLKeysMngrDebugDump		(xmlSecObjPtr obj,
								 FILE* output,
								 size_t level);
static void		xmlSecOpenSSLKeysMngrDebugXmlDump	(xmlSecObjPtr obj,
								 FILE* output,
								 size_t level);


xmlSecKeysMngrPtr 
xmlSecSimpleKeysMngrCreate(void) {
    xmlSecObjPtr tmp;
    
    tmp = xmlSecObjNew(xmlSecOpenSSLKeysMngrKlassId);
    if(tmp == NULL) {
	return(NULL);
    }
    return(xmlSecKeysMngrCast(tmp));
}

/*********************************************************************
 *
 * OpenSSL Keys Manager
 *
 *********************************************************************/
xmlSecObjKlassPtr
xmlSecOpenSSLKeysMngrKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecOpenSSLKeysMngrKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecOpenSSLKeysMngrKlass),
	    "xmlSecOpenSSLKeysMngr",
	    xmlSecOpenSSLKeysMngrKlassInit, 	/* xmlSecObjKlassInitMethod */
	    NULL,				/* xmlSecObjKlassFinalizeMethod */
	    
	    /* obj info */
	    sizeof(xmlSecOpenSSLKeysMngr),
	    xmlSecOpenSSLKeysMngrConstructor,	/* xmlSecObjKlassConstructorMethod */
	    xmlSecOpenSSLKeysMngrDuplicator,	/* xmlSecObjKlassDuplicatorMethod */
	    xmlSecOpenSSLKeysMngrDestructor,	/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
				       &kklassInfo, xmlSecSimpleKeysMngrKlassId); 
    } 
    return(klass);   
}

static void
xmlSecOpenSSLKeysMngrKlassInit(xmlSecObjKlassPtr klass) {
    xmlSecKeysMngrKlassPtr keysMngrKlass = (xmlSecKeysMngrKlassPtr)klass;

    xmlSecAssert(keysMngrKlass != NULL);

    klass->debugDump 		= xmlSecOpenSSLKeysMngrDebugDump;
    klass->debugXmlDump 	= xmlSecOpenSSLKeysMngrDebugXmlDump;
}

static int
xmlSecOpenSSLKeysMngrConstructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr obj) {
    xmlSecOpenSSLKeysMngrPtr keysMngr = xmlSecOpenSSLKeysMngrCast(obj);

    xmlSecAssert2(keysMngr != NULL, -1);
    
#ifndef XMLSEC_NO_X509    
    /* certs list */    
    xmlSecAssert2(keysMngr->x509Store == NULL, -1);
    
    keysMngr->x509Store	= xmlSecOpenSSLX509StoreCreate();    
#endif /* XMLSEC_NO_X509 */	    
    return(0);
}

static int
xmlSecOpenSSLKeysMngrDuplicator(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr dst, xmlSecObjPtr src) {
    xmlSecOpenSSLKeysMngrPtr keysMngrDst = xmlSecOpenSSLKeysMngrCast(dst);
    xmlSecOpenSSLKeysMngrPtr keysMngrSrc = xmlSecOpenSSLKeysMngrCast(src);
    
    xmlSecAssert2(keysMngrDst != NULL, -1);
    xmlSecAssert2(keysMngrSrc != NULL, -1);
    
#ifndef XMLSEC_NO_X509
    xmlSecAssert2(keysMngrSrc->x509Store != NULL, -1);
    xmlSecAssert2(keysMngrDst->x509Store == NULL, -1);
    
    /* todo */
#endif /* XMLSEC_NO_X509 */	    
    return(0);
}

static void
xmlSecOpenSSLKeysMngrDestructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
				    xmlSecObjPtr obj) {
    xmlSecOpenSSLKeysMngrPtr keysMngr = xmlSecOpenSSLKeysMngrCast(obj);

    xmlSecAssert(keysMngr != NULL);
    
#ifndef XMLSEC_NO_X509
    if(keysMngr->x509Store != NULL) {
        xmlSecOpenSSLX509StoreDestroy(keysMngr->x509Store);
    }
#endif /* XMLSEC_NO_X509 */	    
}
    
static void
xmlSecOpenSSLKeysMngrDebugDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecOpenSSLKeysMngrPtr keysMngr = xmlSecOpenSSLKeysMngrCast(obj);

    xmlSecAssert(output != NULL);
    xmlSecAssert(keysMngr != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "simple openssl keys manager:\n");
    /* todo: dump the parent */

#ifndef XMLSEC_NO_X509
    if(keysMngr->x509Store != NULL) {
	/* todo */
    }
#endif /* XMLSEC_NO_X509 */	    
}

static void
xmlSecOpenSSLKeysMngrDebugXmlDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecOpenSSLKeysMngrPtr keysMngr = xmlSecOpenSSLKeysMngrCast(obj);
	    
    xmlSecAssert(output != NULL);
    xmlSecAssert(keysMngr != NULL);
    
    xmlSecObjDebugIndent(output, level);
    fprintf(output, "<OpenSSLKeysMngr>\n");

    /* todo: dump the parent */
#ifndef XMLSEC_NO_X509
    if(keysMngr->x509Store != NULL) {
	/* todo */
    }
#endif /* XMLSEC_NO_X509 */	    

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "</OpenSSLKeysMngr>\n");
}
