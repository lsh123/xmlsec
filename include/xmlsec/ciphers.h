/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_CIPHERS_H__
#define __XMLSEC_CIPHERS_H__    


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 
#include <openssl/evp.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>

typedef struct _xmlSecCipherTransform 		*xmlSecCipherTransformPtr; 
typedef const struct _xmlSecCipherTransformId	*xmlSecCipherTransformId;

typedef int (*xmlSecCipherUpdateMethod)		(xmlSecCipherTransformPtr transform,
						 const unsigned char *buffer,
						 size_t size);
typedef int (*xmlSecCipherFinalMethod)		(xmlSecCipherTransformPtr transform);

struct _xmlSecCipherTransformId {
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
    
    /* xmlSecCipherTransform data/methods */
    xmlSecCipherUpdateMethod		cipherUpdate;
    xmlSecCipherFinalMethod		cipherFinal;
    size_t				keySize;
    size_t				ivSize;
    size_t				bufInSize;
    size_t				bufOutSize;
};

typedef struct _xmlSecCipherTransform {	
    /* same as for xmlSecTransform but id type changed */
    xmlSecCipherTransformId		id;    
    xmlSecTransformStatus		status;
    int					dontDestroy;
    void				*data;
    
    /* xmlSecBinTransform specific */
    int					encode;
    xmlSecCipherTransformPtr		next;
    xmlSecCipherTransformPtr		prev;   
    void				*binData;
    
    /* xmlSecCipherTransform specific */
    unsigned char			*bufIn;
    unsigned char			*bufOut;
    EVP_CIPHER_CTX 			cipherCtx;
    unsigned char			*iv;
    size_t				ivPos;
    void				*cipherData;
} xmlSecCipherTransform;

/**
 * BinTransform methods to be used in the Id structure
 */
XMLSEC_EXPORT int  	xmlSecCipherTransformRead	(xmlSecBinTransformPtr transform, 
							 unsigned char *buf, 
							 size_t size);
XMLSEC_EXPORT int  	xmlSecCipherTransformWrite	(xmlSecBinTransformPtr transform, 
                                        		 const unsigned char *buf, 
							 size_t size);
XMLSEC_EXPORT int  	xmlSecCipherTransformFlush	(xmlSecBinTransformPtr transform);


/**
 * EVP Cipher methods
 */
XMLSEC_EXPORT int 	xmlSecEvpCipherUpdate		(xmlSecCipherTransformPtr cipher,
							 const unsigned char *buffer,
							 size_t size);
XMLSEC_EXPORT int 	xmlSecEvpCipherFinal		(xmlSecCipherTransformPtr cipher);
 
/**
 * Low-level methods
 */
XMLSEC_EXPORT int 	xmlSecCipherUpdate		(xmlSecTransformPtr transform,
							 const unsigned char *buffer,
							 size_t size);
XMLSEC_EXPORT int 	xmlSecCipherFinal		(xmlSecTransformPtr transform);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_CIPHERS_H__ */

