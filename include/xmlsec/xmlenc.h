/** 
 * XMLSec library
 *
 * "XML Encryption" implementation
 *  http://www.w3.org/TR/xmlenc-core
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_XMLENC_H__
#define __XMLSEC_XMLENC_H__    

#ifndef XMLSEC_NO_XMLENC

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 
#include <stdio.h>

#include <libxml/tree.h>
#include <libxml/parser.h> 

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>


typedef struct _xmlSecEncCtx *xmlSecEncCtxPtr; 
typedef struct _xmlSecEncResult *xmlSecEncResultPtr; 

XMLSEC_EXPORT_VAR const xmlChar xmlSecEncTypeElement[]; /* "http://www.w3.org/2001/04/xmlenc#Element"; */
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncTypeContent[]; /* "http://www.w3.org/2001/04/xmlenc#Content"; */

/** 
 * XML Encrypiton context
 */
typedef struct _xmlSecEncCtx {
    /* keys */
    xmlSecKeysMngrPtr		keysMngr;

    xmlSecTransformId		encryptionMethod;  
    
    /* flags */
    int				ignoreType;
} xmlSecEncCtx;

/**
 * XML Encrypiton results
 */
typedef struct _xmlSecEncResult {
    xmlSecEncCtxPtr		ctx;
    void			*context;
    xmlNodePtr			self;
    int				encrypt;
    xmlChar			*id;
    xmlChar			*type;
    xmlChar			*mimeType;
    xmlChar			*encoding;    
    xmlSecTransformId		encryptionMethod;
    xmlSecKeyPtr		key;            
    xmlBufferPtr		buffer;
    int				replaced;
} xmlSecEncResult;

/**
 * XML Encrypiton context methods
 */
XMLSEC_EXPORT xmlSecEncCtxPtr	xmlSecEncCtxCreate	(xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void 		xmlSecEncCtxDestroy	(xmlSecEncCtxPtr ctx);


/**
 * Encryption
 */
XMLSEC_EXPORT int		xmlSecEncryptMemory	(xmlSecEncCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encNode,
							 const unsigned char *buf,
							 size_t size,
							 xmlSecEncResultPtr *result);
XMLSEC_EXPORT int		xmlSecEncryptUri	(xmlSecEncCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encNode,
							 const char *uri,
							 xmlSecEncResultPtr *result);
XMLSEC_EXPORT int		xmlSecEncryptXmlNode	(xmlSecEncCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encNode,
							 xmlNodePtr src,
							 xmlSecEncResultPtr *result);
/**
 * Decryption
 */
XMLSEC_EXPORT int		xmlSecDecrypt		(xmlSecEncCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encDataNode,
							 xmlSecEncResultPtr *result);
/**
 * XML Enc Result
 */		
XMLSEC_EXPORT xmlSecEncResultPtr xmlSecEncResultCreate	(xmlSecEncCtxPtr ctx,
							 void *context,
							 int encrypt,
							 xmlNodePtr node);
XMLSEC_EXPORT void 		xmlSecEncResultDestroy	(xmlSecEncResultPtr result);
XMLSEC_EXPORT void		xmlSecEncResultDebugDump(xmlSecEncResultPtr result,
							 FILE *output);

/** 
 * Encryption Template
 */
XMLSEC_EXPORT xmlNodePtr	xmlSecEncDataCreate	(const xmlChar *id,
							 const xmlChar *type,
							 const xmlChar *mimeType,
							 const xmlChar *encoding);
XMLSEC_EXPORT void 		xmlSecEncDataDestroy	(xmlNodePtr encNode);
XMLSEC_EXPORT xmlNodePtr	xmlSecEncDataAddEncMethod(xmlNodePtr encNode,
							 xmlSecTransformId encMethod);
XMLSEC_EXPORT xmlNodePtr	xmlSecEncDataAddKeyInfo	(xmlNodePtr encNode);							 
XMLSEC_EXPORT xmlNodePtr	xmlSecEncDataAddEncProperties	
							(xmlNodePtr encNode,
							 const xmlChar *id); 
XMLSEC_EXPORT xmlNodePtr	xmlSecEncDataAddEncProperty	
							(xmlNodePtr encNode,
							 const xmlChar *id,
							 const xmlChar *target);
XMLSEC_EXPORT xmlNodePtr	xmlSecEncDataAddCipherValue		
							(xmlNodePtr encNode);
XMLSEC_EXPORT xmlNodePtr	xmlSecEncDataAddCipherReference	
							(xmlNodePtr encNode,
							 const xmlChar *uri);
XMLSEC_EXPORT xmlNodePtr	xmlSecCipherReferenceAddTransform(xmlNodePtr encNode,
							 xmlSecTransformId transform);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_XMLENC */

#endif /* __XMLSEC_XMLENC_H__ */

