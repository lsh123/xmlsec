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

typedef struct _xmlSecCipherTransform 	xmlSecCipherTransform, *xmlSecCipherTransformPtr; 
typedef const struct _xmlSecCipherTransformIdStruct	*xmlSecCipherTransformId;

/**
 * xmlSecCipherUpdateMethod:
 * @transform: the pointer to cipher transform.
 * @buffer: the pointer to data.
 * @size: the data size.
 *
 * Encrypts/decrypts new chunk of data.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int (*xmlSecCipherUpdateMethod)		(xmlSecCipherTransformPtr transform,
						 const unsigned char *buffer,
						 size_t size);
/**
 * xmlSecCipherFinalMethod:
 * @transform: the pointer to cipher transform.
 *
 * Finalizes encryption/decryption.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int (*xmlSecCipherFinalMethod)		(xmlSecCipherTransformPtr transform);

/**
 * xmlSecCipherTransformId:
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
 * @cipherUpdate: the update method.
 * @cipherFinal: the final method.
 * @keySize: the required keys size.
 * @ivSize: the required IV size.
 * @bufInSize: the minimal input buffer size.
 * @bufOutSize: the minimal output buffer size.
 *
 * The cipher (encrypt/decrypt) transform id.
 */
struct _xmlSecCipherTransformIdStruct {
    /* general data */
    const xmlChar*			name;
    xmlSecTransformType			type;
    xmlSecTransformUsage		usage;
    const xmlChar			*href;

    /* general methods */
    xmlSecTransformCreateMethod		create;
    xmlSecTransformDestroyMethod	destroy;
    xmlSecTransformNodeReadMethod	readNode;    
    xmlSecTransformSetKeyRequirements	setKeyReq;
    xmlSecTransformSetKeyMethod		setKey;
    
    /* binary methods */
    xmlSecTransformExecuteBinMethod	executeBin;

    xmlSecTransformReadMethod		readBin; 
    xmlSecTransformWriteMethod		writeBin;
    xmlSecTransformFlushMethod		flushBin;

    /* xml methods */
    xmlSecTransformExecuteXmlMethod	executeXml;

    /* c14n methods */
    xmlSecTransformExecuteC14NMethod	executeC14N;

    /* xmlSecCipherTransform data/methods */
    xmlSecCipherUpdateMethod		cipherUpdate;
    xmlSecCipherFinalMethod		cipherFinal;
    size_t				keySize;
    size_t				ivSize;
    size_t				bufInSize;
    size_t				bufOutSize;
};

/**
 * xmlSecCipherTransform:
 * @id: the transform id (pointer to #xmlSecTransformId).
 * @status: the transform status (ok/fail/unknown).
 * @dontDestroy: the don't automatically destroy flag.
 * @data: the pointer to transform specific data.
 * @encode: encode/decode (encrypt/decrypt) flag.
 * @next: next binary transform in the chain.
 * @prev: previous binary transform in the chain.
 * @binData: the pointer to binary transform speific data.
 * @bufIn: the pointer to input buffer.
 * @bufOut: the pointer to output buffer.
 * @cipherCtx: the EVP chiper context.
 * @iv: the pointer to IV.
 * @ivPos:the position in IV (what was written out).
 * @cipherData: the chipher specific data.
 *
 * The cipher (encrypt/decrypt) transform.
 */
struct _xmlSecCipherTransform {	
    /* general data */
    xmlSecTransformId 			id; 
    xmlSecTransformStatus		status;
    int					dontDestroy;

    /* binary specific */
    int					encode;
    xmlSecTransformPtr			next;
    xmlSecTransformPtr			prev;
    
    /* xml specific */
    xmlNodePtr				hereNode;
    
    void*				reserved0;
    void*				reserved1;
    void*				reserved2;
    void*				reserved3;
    
    /* xmlSecCipherTransform specific */
    unsigned char			*bufIn;
    unsigned char			*bufOut;
    EVP_CIPHER_CTX 			cipherCtx;
    unsigned char			*iv;
    size_t				ivPos;
    void				*cipherData;
};

/**
 * Transform methods to be used in the Id structure
 */
XMLSEC_EXPORT int  	xmlSecCipherTransformRead	(xmlSecTransformPtr transform, 
							 unsigned char *buf, 
							 size_t size);
XMLSEC_EXPORT int  	xmlSecCipherTransformWrite	(xmlSecTransformPtr transform, 
                                        		 const unsigned char *buf, 
							 size_t size);
XMLSEC_EXPORT int  	xmlSecCipherTransformFlush	(xmlSecTransformPtr transform);


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

