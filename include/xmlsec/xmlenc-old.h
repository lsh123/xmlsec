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

typedef struct _xmlSecEncCtx xmlSecEncCtx, *xmlSecEncCtxPtr; 
typedef struct _xmlSecEncResult xmlSecEncResult, *xmlSecEncResultPtr; 


/** 
 * xmlSecEncCtx:
 * @keysMngr: the pointer to keys manager #xmlSecKeysMngr.
 * @encryptionMethod: the default encryption algorithm id.
 * @ignoreType:	the flag to ignore Type attribute in the <enc:EncryptedData> 
 * 	node
 *
 * XML Encrypiton context.
 */
struct _xmlSecEncCtx {
    xmlSecKeyInfoCtx		keyInfoCtx;
    xmlSecTransformId		encryptionMethod;
    int				ignoreType;
    time_t			certsVerificationTime;
};

/**
 * xmlSecEncResult:
 * @ctx: the pointer to #xmlSecEncCtx structure.
 * @context: the pointer to application specific data.
 * @self: the pointer to  <enc:EncryptedData> node.
 * @encrypt: the encrypt/decrypt flag.
 * @id: the Id attribute of the  <enc:EncryptedData> node.
 * @type: the Type attribute of the  <enc:EncryptedData> node.
 * @mimeType: the MimeType attribute of the  <enc:EncryptedData> node.
 * @encoding: the Encoding attribute of the  <enc:EncryptedData> node.
 * @encryptionMethod: the used encryption algorithm id.
 * @key: the used encryption key.
 * @buffer: the decrypted data.
 * @replaced: if set then the decrypted data were put back into the original document.
 *
 * The XML Encrypiton results.
 */
struct _xmlSecEncResult {
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
    xmlSecBufferPtr		buffer;
    int				replaced;
};

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
							 xmlNodePtr encNode,
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
XMLSEC_EXPORT void		xmlSecEncResultDebugXmlDump(xmlSecEncResultPtr result,
							 FILE *output);


