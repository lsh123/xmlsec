/** 
 * XMLSec library
 *
 * Serializable Objects
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_SERIALIZABLE_H__
#define __XMLSEC_SERIALIZABLE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/object.h>

typedef struct _xmlSecSObjKlass				xmlSecSObjKlass,
							*xmlSecSObjKlassPtr;
typedef struct _xmlSecSObj				xmlSecSObj,
							*xmlSecSObjPtr;
typedef struct _xmlSecBufferKlass			xmlSecBufferKlass,
							*xmlSecBufferKlassPtr;
typedef struct _xmlSecBuffer				xmlSecBuffer,
							*xmlSecBufferPtr;

/*********************************************************************
 *
 * Serializable object
 *
 *********************************************************************/
#define xmlSecSObjKlassId 		xmlSecSObjKlassGet()
#define xmlSecSObjKlassCast(klass) 	xmlSecObjKlassCastMacro((klass), xmlSecSObjKlassId, xmlSecSObjKlassPtr)
#define xmlSecSObjKlassCheckCast(klass) xmlSecObjKlassCheckCastMacro((klass), xmlSecSObjKlassId)
#define xmlSecSObjCast(obj) 		xmlSecObjCastMacro((obj), xmlSecSObjKlassId, xmlSecSObjPtr)
#define xmlSecSObjCheckCast(obj) 	xmlSecObjCheckCastMacro((obj), xmlSecSObjKlassId)
	



/** 
 * xmlSecSObjReadXmlMethod:
 * @sobj: the serializable object.
 * @ctx: the read/write context
 *
 * Reading data from XML format.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int		(*xmlSecSObjReadXmlMethod)		(xmlSecSObjPtr sobj,
								 xmlSecObjPtr ctx,
								 xmlNodePtr node);
/** 
 * xmlSecSObjWriteXmlMethod:
 * @sobj: the serializable object.
 * @ctx: the read/write context
 *
 * Writing data in XML format.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int		(*xmlSecSObjWriteXmlMethod)		(xmlSecSObjPtr sobj,
								 xmlSecObjPtr ctx,
								 xmlNodePtr parent);
/** 
 * xmlSecSObjReadBinaryMethod:
 * @sobj: the serializable object.
 * @ctx: the read/write context
 * @buf: the input data buffer.
 * @size: the input data buffer size.
 *
 * Reading binary data method.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int		(*xmlSecSObjReadBinaryMethod)		(xmlSecSObjPtr sobj,
								 xmlSecObjPtr ctx,
								 const unsigned char *buf,
								 size_t size);
/** 
 * xmlSecSObjWriteBinaryMethod:
 * @sobj: the serializable object.
 * @ctx: the read/write context
 * @buf: the pointer to pointer to the output buffer.
 *
 * Writing data in binary format.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int		(*xmlSecSObjWriteBinaryMethod)		(xmlSecSObjPtr sobj,
								 xmlSecObjPtr ctx,
								 xmlSecBufferPtr buf);
struct _xmlSecSObjKlass {
    xmlSecObjKlass			parent;

    const xmlChar*			nodeName;
    const xmlChar*			nodeNs;
    const xmlChar*			typeHref;

    xmlSecSObjReadXmlMethod		readXml;
    xmlSecSObjWriteXmlMethod		writeXml;
    xmlSecSObjReadBinaryMethod		readBinary;
    xmlSecSObjWriteBinaryMethod		writeBinary;
};
		
struct _xmlSecSObj {
    xmlSecObj				parent;
};

XMLSEC_EXPORT xmlSecObjKlassPtr		xmlSecSObjKlassGet	(void);
XMLSEC_EXPORT int			xmlSecSObjReadXml	(xmlSecSObjPtr sobj,
								 xmlSecObjPtr ctx,
								 xmlNodePtr node);
XMLSEC_EXPORT int			xmlSecSObjReadBinary	(xmlSecSObjPtr sobj,
								 xmlSecObjPtr ctx,
								 const unsigned char *buf,
								 size_t size);
XMLSEC_EXPORT int			xmlSecSObjWriteXml	(xmlSecSObjPtr sobj,
								 xmlSecObjPtr ctx,
								 xmlNodePtr node);
XMLSEC_EXPORT int			xmlSecSObjWriteBinary	(xmlSecSObjPtr sobj,
								 xmlSecObjPtr ctx,
								 xmlSecBufferPtr);
    

/*********************************************************************
 *
 * Binary Buffer
 *
 *********************************************************************/
#define xmlSecBufferKlassId 		xmlSecBufferKlassGet()
#define xmlSecBufferKlassCast(klass) 	xmlSecObjKlassCastMacro((klass), xmlSecBufferKlassId, xmlSecBufferKlassPtr)
#define xmlSecBufferKlassCheckCast(klass) xmlSecObjKlassCheckCastMacro((klass), xmlSecBufferKlassId)
#define xmlSecBufferCast(obj) 		xmlSecObjCastMacro((obj), xmlSecBufferKlassId, xmlSecBufferPtr)
#define xmlSecBufferCheckCast(obj) 	xmlSecObjCheckCastMacro((obj), xmlSecBufferKlassId)

struct _xmlSecBufferKlass {
    xmlSecSObjKlass			parent;
};
		
struct _xmlSecBuffer {
    xmlSecSObj				parent;
    
    /* private data */
    unsigned char*			data;
    size_t				size;
    size_t				maxSize;
};

#define xmlSecBufferNew()		((xmlSecBufferPtr)xmlSecObjNew(xmlSecBufferKlassId))

XMLSEC_EXPORT xmlSecObjKlassPtr		xmlSecBufferKlassGet	(void);
XMLSEC_EXPORT unsigned char*		xmlSecBufferGetData	(xmlSecBufferPtr buf);
XMLSEC_EXPORT size_t			xmlSecBufferGetSize	(xmlSecBufferPtr buf);
XMLSEC_EXPORT size_t			xmlSecBufferGetMaxSize	(xmlSecBufferPtr buf);
XMLSEC_EXPORT int			xmlSecBufferSet		(xmlSecBufferPtr buf,
								 const unsigned char* data,
								 size_t size);
XMLSEC_EXPORT int			xmlSecBufferAppend	(xmlSecBufferPtr buf,
								 const unsigned char* data,
								 size_t size);
XMLSEC_EXPORT int			xmlSecBufferPrepend	(xmlSecBufferPtr buf,
								 const unsigned char* data,
								 size_t size);
XMLSEC_EXPORT int			xmlSecBufferInsert	(xmlSecBufferPtr buf,
								 size_t pos,
								 const unsigned char* data,
								 size_t size);
XMLSEC_EXPORT void			xmlSecBufferRemove	(xmlSecBufferPtr buf,
								 size_t pos,
								 size_t size);
XMLSEC_EXPORT void			xmlSecBufferEmpty	(xmlSecBufferPtr buf);
XMLSEC_EXPORT int			xmlSecBufferAllocate	(xmlSecBufferPtr buf,
								 size_t size);
/* base 64 */
XMLSEC_EXPORT xmlChar*			xmlSecBufferBase64Encode(xmlSecBufferPtr buf,
								 int columns);
XMLSEC_EXPORT int			xmlSecBufferBase64Decode(xmlSecBufferPtr buf,
								 const xmlChar* str);

#ifdef __cplusplus
	}
#endif /* __cplusplus */

#endif /* __XMLSEC_SERIALIZABLE_H__ */
