/**
 * xmlSecEncTypeElement:
 * 
 * The element node is encrypted.
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncTypeElement[];

/**
 * xmlSecEncTypeContent:
 *
 * The element node content is encrypted.
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncTypeContent[]; 

typedef struct _xmlSecEncOldCtx xmlSecEncOldCtx, *xmlSecEncOldCtxPtr; 
typedef struct _xmlSecEncResult xmlSecEncResult, *xmlSecEncResultPtr; 


/** 
 * xmlSecEncOldCtx:
 * @keysMngr: the pointer to keys manager #xmlSecKeysMngr.
 * @encryptionMethod: the default encryption algorithm id.
 * @ignoreType:	the flag to ignore Type attribute in the <enc:EncryptedData> 
 * 	node
 *
 * XML Encrypiton context.
 */
struct _xmlSecEncOldCtx {
    xmlSecKeyInfoCtx		keyInfoCtx;
    xmlSecTransformId		encryptionMethod;
    int				ignoreType;
    time_t			certsVerificationTime;
};

/**
 * xmlSecEncResult:
 * @ctx: the pointer to #xmlSecEncOldCtx structure.
 * @context: the pointer to application specific data.
 * @self: the pointer to  <enc:EncryptedData> node.
 * @encrypt: the encrypt/decrypt flag.
 * @encryptionMethod: the used encryption algorithm id.
 * @key: the used encryption key.
 * @buffer: the decrypted data.
 * @replaced: if set then the decrypted data were put back into the original document.
 *
 * The XML Encrypiton results.
 */
struct _xmlSecEncResult {
    xmlSecEncOldCtxPtr		ctx;
    void			*context;
    xmlNodePtr			self;
    int				encrypt;
    xmlChar			*id;
    xmlChar			*type;
    xmlChar			*mimeType;
    xmlChar			*encoding;
    xmlSecTransformId		encryptionMethod;
    xmlSecKeyPtr		key;
    xmlSecBufferPtr		buffer;
    int				replaced;
};

/**
 * XML Encrypiton context methods
 */
XMLSEC_EXPORT xmlSecEncOldCtxPtr	xmlSecEncOldCtxCreate	(xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void 		xmlSecEncOldCtxDestroy	(xmlSecEncOldCtxPtr ctx);


/**
 * Encryption
 */
XMLSEC_EXPORT int		xmlSecEncryptMemory	(xmlSecEncOldCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encNode,
							 const unsigned char *buf,
							 size_t size,
							 xmlSecEncResultPtr *result);
XMLSEC_EXPORT int		xmlSecEncryptUri	(xmlSecEncOldCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encNode,
							 const char *uri,
							 xmlSecEncResultPtr *result);
XMLSEC_EXPORT int		xmlSecEncryptXmlNode	(xmlSecEncOldCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encNode,
							 xmlNodePtr src,
							 xmlSecEncResultPtr *result);
/**
 * Decryption
 */
XMLSEC_EXPORT int		xmlSecDecrypt		(xmlSecEncOldCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encNode,
							 xmlSecEncResultPtr *result);
/**
 * XML Enc Result
 */		
XMLSEC_EXPORT xmlSecEncResultPtr xmlSecEncResultCreate	(xmlSecEncOldCtxPtr ctx,
							 void *context,
							 int encrypt,
							 xmlNodePtr node);
XMLSEC_EXPORT void 		xmlSecEncResultDestroy	(xmlSecEncResultPtr result);
XMLSEC_EXPORT void		xmlSecEncResultDebugDump(xmlSecEncResultPtr result,
							 FILE *output);
XMLSEC_EXPORT void		xmlSecEncResultDebugXmlDump(xmlSecEncResultPtr result,
							 FILE *output);


