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

extern const xmlChar xmlSecEncTypeElement[]; /* "http://www.w3.org/2001/04/xmlenc#Element"; */
extern const xmlChar xmlSecEncTypeContent[]; /* "http://www.w3.org/2001/04/xmlenc#Content"; */

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
xmlSecEncCtxPtr		xmlSecEncCtxCreate		(xmlSecKeysMngrPtr keysMngr);
void 			xmlSecEncCtxDestroy		(xmlSecEncCtxPtr ctx);


/**
 * Encryption
 */
int			xmlSecEncryptMemory		(xmlSecEncCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encNode,
							 const unsigned char *buf,
							 size_t size,
							 xmlSecEncResultPtr *result);
int			xmlSecEncryptUri		(xmlSecEncCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encNode,
							 const char *uri,
							 xmlSecEncResultPtr *result);
int			xmlSecEncryptXmlNode		(xmlSecEncCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encNode,
							 xmlNodePtr src,
							 xmlSecEncResultPtr *result);
/**
 * Decryption
 */
int			xmlSecDecrypt			(xmlSecEncCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encDataNode,
							 xmlSecEncResultPtr *result);
/**
 * XML Enc Result
 */		
xmlSecEncResultPtr	xmlSecEncResultCreate		(xmlSecEncCtxPtr ctx,
							 void *context,
							 int encrypt,
							 xmlNodePtr node);
void 			xmlSecEncResultDestroy		(xmlSecEncResultPtr result);
void			xmlSecEncResultDebugDump	(xmlSecEncResultPtr result,
							 FILE *output);

/** 
 * Encryption Template
 */
xmlNodePtr		xmlSecEncDataCreate		(const xmlChar *id,
							 const xmlChar *type,
							 const xmlChar *mimeType,
							 const xmlChar *encoding);
void 			xmlSecEncDataDestroy		(xmlNodePtr encNode);
xmlNodePtr		xmlSecEncDataAddEncMethod	(xmlNodePtr encNode,
							 xmlSecTransformId encMethod);
xmlNodePtr		xmlSecEncDataAddKeyInfo		(xmlNodePtr encNode);							 
xmlNodePtr		xmlSecEncDataAddEncProperties	(xmlNodePtr encNode,
							 const xmlChar *id); 
xmlNodePtr		xmlSecEncDataAddEncProperty	(xmlNodePtr encNode,
							 const xmlChar *id,
							 const xmlChar *target);
xmlNodePtr		xmlSecEncDataAddCipherValue	(xmlNodePtr encNode);
xmlNodePtr		xmlSecEncDataAddCipherReference	(xmlNodePtr encNode,
							 const xmlChar *uri);
xmlNodePtr		xmlSecCipherReferenceAddTransform(xmlNodePtr encNode,
							 xmlSecTransformId transform);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_XMLENC */

#endif /* __XMLSEC_XMLENC_H__ */

