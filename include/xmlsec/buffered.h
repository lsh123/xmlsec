/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_BUFFERED_H__
#define __XMLSEC_BUFFERED_H__    


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>

typedef const struct _xmlSecBufferedTransformIdStruct	*xmlSecBufferedTransformId;
typedef struct _xmlSecBufferedTransform  		xmlSecBufferedTransform,
							*xmlSecBufferedTransformPtr; 

/** 
 * xmlSecBufferedProcessMethod:
 * @transform: the pointer to buffered transform.
 * @buffer: the pointer to input/output buffer.
 *
 * Processes the data in the buffer.
 *
 * Returns 0 in success or a negative value otherwise.
 */
typedef int (*xmlSecBufferedProcessMethod)	(xmlSecBufferedTransformPtr transform,
						 xmlBufferPtr buffer);

/**
 * xmlSecBufferedTransformId:
 * @type: the type.
 * @usage: the usage.
 * @href: the algorithm href.
 * @create: creation method.
 * @destroy: destroy method.
 * @read: xml node read method.
 * @keyId: the transform's key id.
 * @encryption: the key type (public/private) for encryption.
 * @decryption: the key type (public/private) for encryption.
 * @binSubType: the transform's binary sub type.
 * @addBinKey:  add key method.
 * @readBin: read binary data method.
 * @writeBin: write binary data method.
 * @flushBin: flush binary data method.
 * @bufferedProcess: the buffered process method.
 *
 * The buffered transform id.
 */
struct _xmlSecBufferedTransformIdStruct {
    /* same as xmlSecTransformId */    
    xmlSecTransformType			type;
    xmlSecTransformUsage		usage;
    const xmlChar			*href;
    
    xmlSecTransformCreateMethod		create;
    xmlSecTransformDestroyMethod	destroy;
    xmlSecTransformReadNodeMethod	read;
    
    /* xmlSecBinTransform data/methods */
    xmlSecKeyId				keyId;
    xmlSecKeyType			encryption;
    xmlSecKeyType			decryption;
    xmlSecBinTransformSubType		binSubType;
            
    xmlSecBinTransformAddKeyMethod	addBinKey;
    xmlSecBinTransformReadMethod	readBin;
    xmlSecBinTransformWriteMethod	writeBin;
    xmlSecBinTransformFlushMethod	flushBin;    
    
    /* xmlSecBufferedTransform data/methods */
    xmlSecBufferedProcessMethod		bufferedProcess;
};

/**
 * xmlSecBufferedTransform:
 * @id: the transform id (pointer to #xmlSecBinTransformId).
 * @status: the transform status (ok/fail/unknown).
 * @dontDestroy: the don't automatically destroy flag.
 * @data: the pointer to transform specific data.
 * @encode: encode/decode (encrypt/decrypt) flag.
 * @next: next binary transform in the chain.
 * @prev: previous binary transform in the chain.
 * @binData: the pointer to binary transform speific data.
 * @buffer: the internal buffer.
 *
 * The buffered transform.
 */
struct _xmlSecBufferedTransform {	
    /* same as for xmlSecTransform but id type changed */
    xmlSecBufferedTransformId		id;    
    xmlSecTransformStatus		status;
    int					dontDestroy;
    void				*data;
    
    /* xmlSecBinTransform specific */
    int					encode;
    xmlSecBinTransformPtr		next;
    xmlSecBinTransformPtr		prev;   
    void				*binData;
    
    /* xmlSecBufferedTransform specific */
    xmlBufferPtr			buffer;
};

/**
 * BinTransform methods to be used in the Id structure
 */
XMLSEC_EXPORT int  	xmlSecBufferedTransformRead	(xmlSecBinTransformPtr transform, 
							 unsigned char *buf, 
							 size_t size);
XMLSEC_EXPORT int  	xmlSecBufferedTransformWrite	(xmlSecBinTransformPtr transform, 
                                        		 const unsigned char *buf, 
							 size_t size);
XMLSEC_EXPORT int  	xmlSecBufferedTransformFlush	(xmlSecBinTransformPtr transform);


XMLSEC_EXPORT void 	xmlSecBufferedDestroy		(xmlSecBufferedTransformPtr buffered);
XMLSEC_EXPORT int 	xmlSecBufferedProcess		(xmlSecBinTransformPtr transform,
							 xmlBufferPtr buffer);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_BUFFERED_H__ */

