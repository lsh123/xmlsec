/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_DIGESTS_H__
#define __XMLSEC_DIGESTS_H__    


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>

typedef struct _xmlSecDigestTransform 		*xmlSecDigestTransformPtr; 
typedef const struct _xmlSecDigestTransformId	*xmlSecDigestTransformId;

typedef int (*xmlSecDigestUpdateMethod)		(xmlSecDigestTransformPtr transform,
						 const unsigned char *buffer,
						 size_t size);
typedef int (*xmlSecDigestSignMethod)		(xmlSecDigestTransformPtr transform,
						 unsigned char **buffer,
						 size_t *size);
typedef int (*xmlSecDigestVerifyMethod)		(xmlSecDigestTransformPtr transform,
						 const unsigned char *buffer,
						 size_t size);

struct _xmlSecDigestTransformId {
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
    
    /* xmlSecDigestTransform data/methods */
    xmlSecDigestUpdateMethod		digestUpdate;
    xmlSecDigestSignMethod		digestSign;
    xmlSecDigestVerifyMethod		digestVerify;
};

typedef struct _xmlSecDigestTransform {	
    /* same as for xmlSecTransform but id type changed */
    xmlSecDigestTransformId		id;    
    xmlSecTransformStatus		status;
    int					dontDestroy;
    void				*data;
    
    /* xmlSecBinTransform specific */
    int					encode;
    xmlSecDigestTransformPtr		next;
    xmlSecDigestTransformPtr		prev;   
    void				*binData;
    
    /* xmlSecDigestTransform specific */
    int					pushModeEnabled; /* if 1 then the data are sent
						 	  * to next transform, otherwise
							  * we are keeping data for sign 
							  * or verify call */
    unsigned char			*digest;
    size_t				digestSize;
    void 				*digestData;
} xmlSecDigestTransform;

/** 
 * Digest specific hi-level methods
 */ 
int 	xmlSecDigestSignNode				(xmlSecTransformPtr transform,
							 xmlNodePtr valueNode,
							 int removeOldContent);
int 	xmlSecDigestVerifyNode				(xmlSecTransformPtr transform,
							 const xmlNodePtr valueNode);
void	xmlSecDigestSetPushMode				(xmlSecTransformPtr transform,
							 int enabled);

/** 
 * Digest specific low-level methods
 */ 
int 	xmlSecDigestUpdate				(xmlSecTransformPtr transform,
							 const unsigned char *buffer,
							 size_t size);
int 	xmlSecDigestSign				(xmlSecTransformPtr transform,
							 unsigned char **buffer,
							 size_t *size);
int 	xmlSecDigestVerify				(xmlSecTransformPtr transform,
							 const unsigned char *buffer,
							 size_t size);


/**
 * BinTransform methods to be used in the Id structure
 */
int  	xmlSecDigestTransformRead			(xmlSecBinTransformPtr transform, 
							 unsigned char *buf, 
							 size_t size);
int  	xmlSecDigestTransformWrite			(xmlSecBinTransformPtr transform, 
                                        		 const unsigned char *buf, 
							 size_t size);
int  	xmlSecDigestTransformFlush			(xmlSecBinTransformPtr transform);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_DIGESTS_H__ */

