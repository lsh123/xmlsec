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
#include <openssl/evp.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>

typedef struct _xmlSecBufferedTransform 	*xmlSecBufferedTransformPtr; 
typedef const struct _xmlSecBufferedTransformId	*xmlSecBufferedTransformId;

typedef int (*xmlSecBufferedProcessMethod)	(xmlSecBufferedTransformPtr transform,
						 xmlBufferPtr buffer);

struct _xmlSecBufferedTransformId {
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

typedef struct _xmlSecBufferedTransform {	
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
} xmlSecBufferedTransform;

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

