/** 
 * XMLSec library
 *
 * KeyInfo node processing
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_KEYINFO_H__
#define __XMLSEC_KEYINFO_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <time.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/list.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keys.h>

/**
 * Hi level functions
 */
XMLSEC_EXPORT int	 	xmlSecKeyInfoNodeRead		(xmlNodePtr keyInfoNode,
								 xmlSecKeyPtr key,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int 		xmlSecKeyInfoNodeWrite		(xmlNodePtr keyInfoNode,
								 xmlSecKeyPtr key,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);

typedef unsigned int		xmlSecUriType;
#define xmlSecUriTypeNone		0x0000
#define xmlSecUriTypeLocalEmpty		0x0001
#define xmlSecUriTypeLocalXPointer	0x0002		
#define xmlSecUriTypeRemote		0x0004
#define xmlSecUriTypeAny		0xFFFF

/**		
 * xmlSecKeyInfoCtx:
 *
 */
struct _xmlSecKeyInfoCtx {
    void*				userData;
    xmlSecKeysMngrPtr			keysMngr;
    int					base64LineSize;
    xmlSecPtrListPtr			allowedKeyDataIds;
    int					stopWhenKeyFound;
    int					stopWhenUnknownNodeFound;
        
    /* RetrievalMethod */
    xmlSecTransformCtxPtr		transformCtx;
    xmlSecUriType			allowedRetrievalMethodUris;
    int 				maxRetrievalMethodLevel;
    int					stopWhenUnknownRetrievalMethodHrefFound;

    /* EncryptedKey */
    xmlSecEncCtxPtr			encCtx;
    int					maxEncryptedKeyLevel; 
    int					failIfDecryptionFails;
	    
    /* x509 certificates */
    int					failIfCertNotFound;
    time_t				certsVerificationTime;
    int					certsVerificationDepth;
    
    /* internal data */
    int 				curRetrievalMethodLevel;
    int					curEncryptedKeyLevel;                
    xmlSecKeyReq			keyReq;
};

XMLSEC_EXPORT xmlSecKeyInfoCtxPtr 	xmlSecKeyInfoCtxCreate		(xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void			xmlSecKeyInfoCtxDestroy		(xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int			xmlSecKeyInfoCtxInitialize	(xmlSecKeyInfoCtxPtr keyInfoCtx,
									 xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void			xmlSecKeyInfoCtxFinalize	(xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int 			xmlSecKeyInfoCtxCreateEncCtx	(xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int			xmlSecKeyInfoCtxCopyUserPref	(xmlSecKeyInfoCtxPtr dst,
									 xmlSecKeyInfoCtxPtr src);
XMLSEC_EXPORT int			xmlSecKeyInfoCtxEnableKeyData	(xmlSecKeyInfoCtxPtr keyInfoCtx,
									 xmlSecKeyDataId dataId);
XMLSEC_EXPORT int			xmlSecKeyInfoCtxEnableKeyDataByName(xmlSecKeyInfoCtxPtr keyInfoCtx,
									 const xmlChar* name);


/**
 * xmlSecKeyDataNameId
 *
 * The <dsig:KeyName> processing class.
 */
#define xmlSecKeyDataNameId	xmlSecKeyDataNameGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId	xmlSecKeyDataNameGetKlass		(void);

/**
	 * xmlSecKeyDataValueId
 *
 * The <dsig:KeyValue> processing class.
 */
#define xmlSecKeyDataValueId	xmlSecKeyDataValueGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId	xmlSecKeyDataValueGetKlass		(void);

/**
 * xmlSecKeyDataRetrievalMethodId
 *
 * The <dsig:RetrievalMethod> processing class.
 */
#define xmlSecKeyDataRetrievalMethodId	xmlSecKeyDataRetrievalMethodGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId	xmlSecKeyDataRetrievalMethodGetKlass	(void);

#ifndef XMLSEC_NO_XMLENC
/**
 * xmlSecKeyDataEncryptedKeyId
 *
 * The <enc:EncryptedKey> processing class.
 */
#define xmlSecKeyDataEncryptedKeyId	xmlSecKeyDataEncryptedKeyGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId	xmlSecKeyDataEncryptedKeyGetKlass	(void);
#endif /* XMLSEC_NO_XMLENC */


		    
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYINFO_H__ */

