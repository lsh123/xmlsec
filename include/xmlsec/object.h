/** 
 * XMLSec library
 *
 * Objects/classes system. It is similar to one found in GLib/GTK/GDK.
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_OBJECT_H__
#define __XMLSEC_OBJECT_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <xmlsec/xmlsec.h>

typedef void*						xmlSecPtr;
typedef struct _xmlSecObjKlassInfo			xmlSecObjKlassInfo,
							*xmlSecObjKlassInfoPtr;
typedef struct _xmlSecObjKlass				xmlSecObjKlass,
							*xmlSecObjKlassPtr;
typedef struct _xmlSecObj				xmlSecObj,
							*xmlSecObjPtr;

/*********************************************************************
 *
 * klasses registration and creation helpers
 *
 ********************************************************************/
/* macros used for creating klass/object specific ones */	
#define xmlSecObjKlassCastMacro(klass, dstKlass, dstKlassName) \
	((dstKlassName)xmlSecObjKlassCheckCastFunc((xmlSecObjKlassPtr)(klass), (dstKlass)))
#define xmlSecObjKlassCheckCastMacro(klass, dstKlass) \
	(xmlSecObjKlassCastMacro((klass), (dstKlass), xmlSecPtr) != (xmlSecPtr)NULL)
#define xmlSecObjCastMacro(obj, dstKlass, dstObjName) \
	((xmlSecObjKlassCheckCastMacro(xmlSecObjGetKlass((obj)), (dstKlass))) ? \
	(dstObjName)obj : (dstObjName)NULL)
#define xmlSecObjCheckCastMacro(obj, dstKlass) \
	(xmlSecObjCastMacro((obj), (dstKlass), xmlSecPtr) != (xmlSecPtr)NULL) 

#define xmlSecObjKlassGetKlassInfo(kl) \
	(((kl) != NULL) ? \
	((xmlSecObjKlassPtr)(kl))->klassInfo : NULL)
#define xmlSecObjGetKlass(obj) \
	(((obj) != NULL) ? \
	(((xmlSecObjPtr)(obj))->klass) : (xmlSecObjKlassPtr)NULL)
#define xmlSecObjGetKlassInfo(obj) \
	(xmlSecObjKlassGetKlassInfo(xmlSecObjGetKlass((obj))))	

XMLSEC_EXPORT xmlSecObjKlassPtr 	xmlSecObjKlassRegister	   (xmlSecPtr buf,
								    size_t size,
								    xmlSecObjKlassInfoPtr klassInfo,
								    xmlSecObjKlassPtr parent);
XMLSEC_EXPORT const char*		xmlSecObjKlassGetKlassName (const xmlSecObjKlassPtr klass);
XMLSEC_EXPORT xmlSecObjKlassPtr		xmlSecObjKlassCheckCastFunc(const xmlSecObjKlassPtr klass,
    								    const xmlSecObjKlassPtr dst);

/*********************************************************************
 *
 * Klass Info
 *
 *********************************************************************/
typedef void		(*xmlSecObjKlassInitMethod)		(xmlSecObjKlassPtr klass);
typedef void		(*xmlSecObjKlassFinalizeMethod)		(xmlSecObjKlassPtr klass);
typedef int		(*xmlSecObjKlassConstructorMethod)	(xmlSecObjKlassPtr klass,
								 xmlSecObjPtr obj);
typedef int		(*xmlSecObjKlassDuplicatorMethod)	(xmlSecObjKlassPtr klass,
						    	         xmlSecObjPtr dst, 
								 xmlSecObjPtr src);
typedef void		(*xmlSecObjKlassDestructorMethod)	(xmlSecObjKlassPtr klass,
						    		 xmlSecObjPtr dst);

struct _xmlSecObjKlassInfo {
    /* klass data */
    size_t				klassSize;
    const char*				klassName;
    xmlSecObjKlassInitMethod		klassInit;
    xmlSecObjKlassFinalizeMethod	klassFinalize;
    
    /* obj info */  
    size_t				objSize;
    xmlSecObjKlassConstructorMethod 	objConstructor;
    xmlSecObjKlassDuplicatorMethod	objDuplicator;
    xmlSecObjKlassDestructorMethod  	objDestructor;
};


/*********************************************************************
 *
 * new/delete methods
 *
 ********************************************************************/
XMLSEC_EXPORT xmlSecObjPtr		xmlSecObjNew		(xmlSecObjKlassPtr klass);
XMLSEC_EXPORT xmlSecObjPtr		xmlSecObjDuplicate	(xmlSecObjPtr obj);
XMLSEC_EXPORT void			xmlSecObjDelete		(xmlSecObjPtr obj);

/*********************************************************************
 *
 * Base Object
 *
 *********************************************************************/
#define xmlSecObjKlassId 		xmlSecObjKlassGet()
#define xmlSecObjKlassCast(klass) 	xmlSecObjKlassCastMacro((klass), xmlSecObjKlassId, xmlSecObjKlassPtr)
#define xmlSecObjKlassCheckCast(klass) 	xmlSecObjKlassCheckCastMacro((klass), xmlSecObjKlassId)
#define xmlSecObjCast(obj) 		xmlSecObjCastMacro((obj), xmlSecObjKlassId, xmlSecObjPtr)
#define xmlSecObjCheckCast(obj) 	xmlSecObjCheckCastMacro((obj), xmlSecObjKlassId)
	
typedef void 		(*xmlSecObjDebugDumpMethod)		(xmlSecObjPtr obj,
								 FILE* output,
								 size_t level);
struct _xmlSecObjKlass {
    xmlSecObjKlassInfoPtr		klassInfo;
    xmlSecObjKlassPtr			klassParent;

    xmlSecObjDebugDumpMethod		debugDump;
    xmlSecObjDebugDumpMethod		debugXmlDump;
};
		
struct _xmlSecObj {
    xmlSecObjKlassPtr			klass;
};

XMLSEC_EXPORT xmlSecObjKlassPtr		xmlSecObjKlassGet	(void);
XMLSEC_EXPORT void			xmlSecObjDebugDump	(xmlSecObjPtr obj,
								 FILE* output,
								 size_t level);
XMLSEC_EXPORT void			xmlSecObjDebugXmlDump	(xmlSecObjPtr obj,
								 FILE* output,
								 size_t level);
XMLSEC_EXPORT void			xmlSecObjDebugIndent	(FILE* output,
								 size_t level);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OBJECT_H__ */
