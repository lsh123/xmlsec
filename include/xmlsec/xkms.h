/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * "XML Key Management Specification v 2.0" implementation
 *  http://www.w3.org/TR/xkms2/
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_XKMS_H__
#define __XMLSEC_XKMS_H__    

#ifndef XMLSEC_NO_XKMS
	
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 
#include <stdio.h>		

#include <libxml/tree.h>
#include <libxml/parser.h> 

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/list.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>

typedef struct _xmlSecXkmsRespondWithKlass	xmlSecXkmsRespondWithKlass, 
						*xmlSecXkmsRespondWithId;


/**
 * xmlXkmsCtxMode:
 * @xmlXkmsCtxModeLocateRequest: 	the <xkms:LocateRequest/> node processing.
 * @xmlXkmsCtxModeValidateRequest:	the <xkms:ValidateRequest/> node processing.
 *
 * XKMS request processing mode.
 */
typedef enum {
    xmlXkmsCtxModeLocateRequest = 0,
    xmlXkmsCtxModeValidateRequest
} xmlXkmsCtxMode;

/** 
 * xmlSecXkmsCtx:
 * @userData:			the pointer to user data (xmlsec and xmlsec-crypto libraries
 *				never touches this).
 * @flags:			the XML Encryption processing flags.
 * @flags2:			the XML Encryption processing flags.
 * @keyInfoReadCtx:		the reading key context.
 * @keyInfoWriteCtx:		the writing key context (not used for signature verification).
 * @reserved0:			reserved for the future.
 * @reserved1:			reserved for the future.
 * 
 * XKMS context.
 */
struct _xmlSecXkmsCtx {
    /* these data user can set before performing the operation */
    void*			userData;
    unsigned int		flags;
    unsigned int		flags2;    
    xmlSecKeyInfoCtx		keyInfoReadCtx;
    xmlSecKeyInfoCtx		keyInfoWriteCtx;
    xmlSecPtrList		enabledRespondWith;
    
    /* these data are returned */
    xmlDocPtr			result;
    xmlSecPtrList		keys;

    /* these are internal data, nobody should change that except us */
    xmlXkmsCtxMode		mode;
    xmlNodePtr			opaqueClientDataNode;
    xmlNodePtr 			firtsMsgExtNode;
    xmlNodePtr 			firtsRespMechNode;
    xmlNodePtr 			keyInfoNode;
    xmlSecPtrList		respWithList;
    
    /* reserved for future */
    void*			reserved0;
    void*			reserved1;
};

XMLSEC_EXPORT xmlSecXkmsCtxPtr	xmlSecXkmsCtxCreate		(xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void 		xmlSecXkmsCtxDestroy		(xmlSecXkmsCtxPtr xkmsCtx);
XMLSEC_EXPORT int		xmlSecXkmsCtxInitialize		(xmlSecXkmsCtxPtr xkmsCtx,
								 xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void		xmlSecXkmsCtxFinalize		(xmlSecXkmsCtxPtr xkmsCtx);
XMLSEC_EXPORT int		xmlSecXkmsCtxCopyUserPref	(xmlSecXkmsCtxPtr dst,
								 xmlSecXkmsCtxPtr src);
XMLSEC_EXPORT void		xmlSecXkmsCtxReset		(xmlSecXkmsCtxPtr xkmsCtx);
XMLSEC_EXPORT int		xmlSecXkmsCtxLocate		(xmlSecXkmsCtxPtr xkmsCtx,
								 xmlNodePtr node);
XMLSEC_EXPORT int		xmlSecXkmsCtxValidate		(xmlSecXkmsCtxPtr xkmsCtx,
								 xmlNodePtr node);
XMLSEC_EXPORT void		xmlSecXkmsCtxDebugDump		(xmlSecXkmsCtxPtr xkmsCtx,
								 FILE* output);
XMLSEC_EXPORT void		xmlSecXkmsCtxDebugXmlDump	(xmlSecXkmsCtxPtr xkmsCtx,
								 FILE* output);


/**********************************************************************
 *
 * Hi-level functions
 *
 *********************************************************************/
XMLSEC_EXPORT xmlSecPtrListPtr	xmlSecXkmsRespondWithIdsGet	(void);
XMLSEC_EXPORT int 		xmlSecXkmsRespondWithIdsInit	(void);
XMLSEC_EXPORT void 		xmlSecXkmsRespondWithIdsShutdown(void);
XMLSEC_EXPORT int 		xmlSecXkmsRespondWithIdsRegisterDefault(void);
XMLSEC_EXPORT int		xmlSecXkmsRespondWithIdsRegister(xmlSecXkmsRespondWithId id);

/************************************************************************
 *
 * XKMS RespondWith Klass
 *
 ************************************************************************/ 
XMLSEC_EXPORT int  		xmlSecXkmsRespondWithReadNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsCtxPtr xkmsCtx,
								 xmlNodePtr node);
XMLSEC_EXPORT int  		xmlSecXkmsRespondWithWriteNode	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsCtxPtr xkmsCtx,
								 xmlNodePtr node);
XMLSEC_EXPORT void		xmlSecXkmsRespondWithDebugDump	(xmlSecXkmsRespondWithId id,
								 FILE* output);
XMLSEC_EXPORT void		xmlSecXkmsRespondWithDebugXmlDump(xmlSecXkmsRespondWithId id,
								 FILE* output);
XMLSEC_EXPORT int  		xmlSecXkmsRespondWithDefaultReadNode(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsCtxPtr xkmsCtx,
								 xmlNodePtr node);
XMLSEC_EXPORT int  		xmlSecXkmsRespondWithDefaultWriteNode(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsCtxPtr xkmsCtx,
								 xmlNodePtr node);

typedef int  		(*xmlSecXkmsRespondWithReadNodeMethod)	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsCtxPtr xkmsCtx,
								 xmlNodePtr node);
typedef int  		(*xmlSecXkmsRespondWithWriteNodeMethod)	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsCtxPtr xkmsCtx,
								 xmlNodePtr node);
struct _xmlSecXkmsRespondWithKlass {
    const xmlChar*				name;
    const xmlChar*				nodeName;
    const xmlChar*				nodeNs;
    
    xmlSecXkmsRespondWithReadNodeMethod		readNode;
    xmlSecXkmsRespondWithWriteNodeMethod	writeNode;
};

#define xmlSecXkmsRespondWithKlassGetName(id) \
	((((id) != NULL) && ((id)->name != NULL)) ? (id)->name : NULL)

/************************************************************************
 *
 * XKMS RespondWith Klass List
 *
 ************************************************************************/ 
/**
 * xmlSecXkmsRespondWithIdListId:
 *
 * XKMS RespondWith  klasses list klass.
 */
#define xmlSecXkmsRespondWithIdListId	xmlSecXkmsRespondWithIdListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId	xmlSecXkmsRespondWithIdListGetKlass(void);
XMLSEC_EXPORT int		xmlSecXkmsRespondWithIdListFind	(xmlSecPtrListPtr list,
								 xmlSecXkmsRespondWithId id);
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithIdListFindByName
								(xmlSecPtrListPtr list,
								 const xmlChar* name);
XMLSEC_EXPORT int		xmlSecXkmsRespondWithIdListWrite(xmlSecPtrListPtr list,
								 xmlSecXkmsCtxPtr xkmsCtx,
								 xmlNodePtr node);

/******************************************************************** 
 *
 * XML Sec Library RespondWith Ids
 *
 *******************************************************************/
/**
 * xmlSecXkmsRespondWithIdUnknown:
 *
 * The "unknown" RespondWith id (NULL).
 */
#define xmlSecXkmsRespondWithIdUnknown			NULL

/**
 * xmlSecXkmsRespondWithKeyNameId:
 *
 * The respond with KeyName klass.
 */ 
#define xmlSecXkmsRespondWithKeyNameId \
	xmlSecXkmsRespondWithKeyNameGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithKeyNameGetKlass(void);

/**
 * xmlSecXkmsRespondWithKeyValueId:
 *
 * The respond with KeyValue klass.
 */ 
#define xmlSecXkmsRespondWithKeyValueId \
	xmlSecXkmsRespondWithKeyValueGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithKeyValueGetKlass(void);

/**
 * xmlSecXkmsRespondWithPrivateKeyId:
 *
 * The respond with PrivateKey klass.
 */ 
#define xmlSecXkmsRespondWithPrivateKeyId \
	xmlSecXkmsRespondWithPrivateKeyGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithPrivateKeyGetKlass(void);

/**
 * xmlSecXkmsRespondWithRetrievalMethodId:
 *
 * The respond with RetrievalMethod klass.
 */ 
#define xmlSecXkmsRespondWithRetrievalMethodId \
	xmlSecXkmsRespondWithRetrievalMethodGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithRetrievalMethodGetKlass(void);

/**
 * xmlSecXkmsRespondWithX509CertId:
 *
 * The respond with X509Cert klass.
 */ 
#define xmlSecXkmsRespondWithX509CertId \
	xmlSecXkmsRespondWithX509CertGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithX509CertGetKlass(void);

/**
 * xmlSecXkmsRespondWithX509ChainId:
 *
 * The respond with X509Chain klass.
 */ 
#define xmlSecXkmsRespondWithX509ChainId \
	xmlSecXkmsRespondWithX509ChainGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithX509ChainGetKlass(void);

/**
 * xmlSecXkmsRespondWithX509CRLId:
 *
 * The respond with X509CRL klass.
 */ 
#define xmlSecXkmsRespondWithX509CRLId \
	xmlSecXkmsRespondWithX509CRLGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithX509CRLGetKlass(void);


/**
 * xmlSecXkmsRespondWithPGPId:
 *
 * The respond with PGP klass.
 */ 
#define xmlSecXkmsRespondWithPGPId \
	xmlSecXkmsRespondWithPGPGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithPGPGetKlass(void);

/**
 * xmlSecXkmsRespondWithSPKIId:
 *
 * The respond with SPKI klass.
 */ 
#define xmlSecXkmsRespondWithSPKIId \
	xmlSecXkmsRespondWithSPKIGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithSPKIGetKlass(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_XKMS */

#endif /* __XMLSEC_XKMS_H__ */

