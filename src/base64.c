/**
 * XMLSec library
 *
 * Base64 encode/decode transform
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/ciphers.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

/* 
 * the table to map numbers to base64 
 */
static const unsigned char base64[] =
{  
/*   0    1    2    3    4    5    6    7   */
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', /* 0 */
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', /* 1 */
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', /* 2 */
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', /* 3 */
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', /* 4 */
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', /* 5 */
    'w', 'x', 'y', 'z', '0', '1', '2', '3', /* 6 */
    '4', '5', '6', '7', '8', '9', '+', '/'  /* 7 */
};


/* few macros to simplify the code */
#define	XMLSEC_BASE64_INPUT_BUFFER_SIZE		64
#define	XMLSEC_BASE64_OUTPUT_BUFFER_SIZE	5*XMLSEC_BASE64_INPUT_BUFFER_SIZE

#define xmlSecBase64Encode1(a) 		(base64[((int)(a) >> 2) & 0x3F])
#define xmlSecBase64Encode2(a, b) 	(base64[(((int)(a) << 4) & 0x30) + ((((int)(b)) >> 4) & 0x0F)])
#define xmlSecBase64Encode3(b, c) 	(base64[(((int)(b) << 2) & 0x3c) + ((((int)(c)) >> 6) & 0x03)])
#define xmlSecBase64Encode4( c)		(base64[((int)(c)) & 0x3F])

#define xmlSecBase64Decode1(a, b)	(((a) << 2) | (((b) & 0x3F) >> 4))
#define xmlSecBase64Decode2(b, c)	(((b) << 4) | (((c) & 0x3F) >> 2))
#define xmlSecBase64Decode3(c, d)	(((c) << 6) | ((d) & 0x3F))
	
#define xmlSecIsBase64Char(ch) 		((((ch) >= 'A') && ((ch) <= 'Z')) || \
					 (((ch) >= 'a') && ((ch) <= 'z')) || \
					 (((ch) >= '0') && ((ch) <= '9')) || \
					  ((ch) == '+') || ((ch) == '/')) 

/**
 *
 * Base64 Context
 *
 */

struct _xmlSecBase64Ctx {
    int			encode;
    
    unsigned char	in[4];
    unsigned char	out[16];
    size_t 		inPos;
    
    size_t		linePos;
    size_t		columns;    
    int			equalSigns;
};


static int		xmlSecBase64CtxEncode		(xmlSecBase64CtxPtr ctx);
static int		xmlSecBase64CtxDecode		(xmlSecBase64CtxPtr ctx);




static xmlSecTransformPtr xmlSecBase64Create		(xmlSecTransformId id);
static void		xmlSecBase64Destroy		(xmlSecTransformPtr transform);
static int  		xmlSecBase64Update		(xmlSecCipherTransformPtr transform, 
							 const unsigned char *buf, 
							 size_t size);
static int  		xmlSecBase64Final		(xmlSecCipherTransformPtr transform);
							 
static const struct _xmlSecCipherTransformIdStruct xmlSecBase64EncodeId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    0,					/* xmlSecAlgorithmUsage usage; */
    NULL,				/* const xmlChar href; */

    xmlSecBase64Create, 		/* xmlSecTransformCreateMethod create; */
    xmlSecBase64Destroy,		/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    xmlSecKeyIdUnknown,
    xmlSecKeyTypeAny,			/* xmlSecKeyType encryption; */
    xmlSecKeyTypeAny,			/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeCipher,
    NULL,				/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecCipherTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecCipherTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecCipherTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */

    /* xmlSecCipherTransform data/methods */
    xmlSecBase64Update,			/* xmlSecCipherUpdateMethod cipherUpdate; */
    xmlSecBase64Final,			/* xmlSecCipherFinalMethod cipherFinal; */
    0,					/* size_t keySize; */
    0,					/* size_t ivSize; */
    XMLSEC_BASE64_INPUT_BUFFER_SIZE,	/* size_t bufInSize */
    XMLSEC_BASE64_OUTPUT_BUFFER_SIZE	/* size_t bufOutSize */
};
xmlSecTransformId xmlSecEncBase64Encode = (xmlSecTransformId)&xmlSecBase64EncodeId;

static const struct _xmlSecCipherTransformIdStruct xmlSecBase64DecodeId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageDSigTransform,		/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2000/09/xmldsig#base64",	/* const xmlChar href; */

    xmlSecBase64Create, 		/* xmlSecTransformCreateMethod create; */
    xmlSecBase64Destroy,		/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    xmlSecKeyIdUnknown,
    xmlSecKeyTypeAny,			/* xmlSecKeyType encryption; */
    xmlSecKeyTypeAny,			/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeCipher,
    NULL,				/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecCipherTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecCipherTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecCipherTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */

    /* xmlSecCipherTransform data/methods */
    xmlSecBase64Update,			/* xmlSecCipherUpdateMethod cipherUpdate; */
    xmlSecBase64Final,			/* xmlSecCipherFinalMethod cipherFinal; */
    0,					/* size_t keySize; */
    0,					/* size_t ivSize; */
    XMLSEC_BASE64_INPUT_BUFFER_SIZE,	/* size_t bufInSize */
    XMLSEC_BASE64_INPUT_BUFFER_SIZE	/* size_t bufOutSize */    
};
xmlSecTransformId xmlSecEncBase64Decode = (xmlSecTransformId)&xmlSecBase64DecodeId;


/**************************************************************
 *
 * Base64 Transform
 *
 **************************************************************/

/**
 * xmlSecBase64EncodeSetLineSize:
 * @transform: the pointer to BASE64 encode transform.
 * @lineSize: the new max line size.
 *
 * Sets the max line size to @lineSize.
 */
void
xmlSecBase64EncodeSetLineSize(xmlSecTransformPtr transform, size_t lineSize) {
    xmlSecBase64CtxPtr ctx;  
    
    xmlSecAssert(transform != NULL);
    
    if(!xmlSecTransformCheckId(transform, xmlSecEncBase64Encode) ||
       (transform->data == NULL)) {
       
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncBase64Encode");
	return;
    }
    ctx = (xmlSecBase64CtxPtr)(transform->data);
    ctx->columns = lineSize;    
}

/**
 * xmlSecBase64Create:
 */
static xmlSecTransformPtr 
xmlSecBase64Create(xmlSecTransformId id) {
    xmlSecCipherTransformPtr cipher;
    int encode;
    
    xmlSecAssert2(id != NULL, NULL);
    
    if(id == xmlSecEncBase64Encode) {
	encode = 1;
    } else if(id == xmlSecEncBase64Decode) {
	encode = 0;
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncBase64Encode,xmlSecEncBase64Decode");
	return(NULL);	
    }
    
    cipher = (xmlSecCipherTransformPtr)xmlMalloc(sizeof(xmlSecCipherTransform) +
		 sizeof(unsigned char) * (XMLSEC_BASE64_OUTPUT_BUFFER_SIZE + 
					  XMLSEC_BASE64_INPUT_BUFFER_SIZE));    
    if(cipher == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_MALLOC_FAILED,	
		    "%d",
		    XMLSEC_BASE64_OUTPUT_BUFFER_SIZE + XMLSEC_BASE64_INPUT_BUFFER_SIZE);
	return(NULL);
    }
    memset(cipher, 0, sizeof(xmlSecCipherTransform) + 
		 sizeof(unsigned char) * (XMLSEC_BASE64_INPUT_BUFFER_SIZE + 
		 XMLSEC_BASE64_OUTPUT_BUFFER_SIZE));

    cipher->id = (xmlSecCipherTransformId)id;
    cipher->encode = encode;    
    cipher->bufIn = ((unsigned char*)cipher) + sizeof(xmlSecCipherTransform);
    cipher->bufOut = cipher->bufIn + cipher->id->bufInSize;
        
    cipher->data = xmlSecBase64CtxCreate(encode, XMLSEC_BASE64_LINESIZE);    
    if(cipher->data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64CtxCreate");
	xmlSecTransformDestroy((xmlSecTransformPtr)cipher, 1);	
	return(NULL);
    }
    
    return((xmlSecTransformPtr)cipher);
}

/**
 * xmlSecBase64Destroy:
 */
static void
xmlSecBase64Destroy(xmlSecTransformPtr transform) {
    xmlSecCipherTransformPtr cipher;
    
    xmlSecAssert(transform != NULL);
    
    if(!xmlSecTransformCheckId(transform, xmlSecEncBase64Encode) &&
       !xmlSecTransformCheckId(transform, xmlSecEncBase64Decode)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncBase64Encode,xmlSecEncBase64Decode");
	return;
    }
    
    cipher = (xmlSecCipherTransformPtr) transform;
    if(cipher->data != NULL) {
	xmlSecBase64CtxDestroy((xmlSecBase64CtxPtr)transform->data);
    }    
    memset(cipher, 0, sizeof(xmlSecCipherTransform) + 
		      sizeof(unsigned char) * (XMLSEC_BASE64_INPUT_BUFFER_SIZE + 
		    			       XMLSEC_BASE64_OUTPUT_BUFFER_SIZE));
    xmlFree(cipher);
}

/**
 * xmlSecBase64Update:
 */
static int
xmlSecBase64Update(xmlSecCipherTransformPtr cipher, 
		 const unsigned char *buf, size_t size) {
    xmlSecBase64CtxPtr ctx;
    int ret;
    
    xmlSecAssert2(cipher != NULL, -1);
        
    if(!xmlSecTransformCheckId(cipher, xmlSecEncBase64Encode) &&
       !xmlSecTransformCheckId(cipher, xmlSecEncBase64Decode)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncBase64Encode,xmlSecEncBase64Decode");
	return(-1);
    }
    
    if((buf == NULL) || (size == 0)) {
	return(0);
    }


    ctx = (xmlSecBase64CtxPtr)cipher->data;
    if(size > cipher->id->bufInSize) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_INVALID_TRANSFORM_DATA,
		    " ");
	return(-1);
    }
    
    ret = xmlSecBase64CtxUpdate(ctx, buf, size, cipher->bufOut, cipher->id->bufOutSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    " ");
	return(-1);
    }
    return(ret);
}

static int
xmlSecBase64Final(xmlSecCipherTransformPtr cipher) {
    xmlSecBase64CtxPtr ctx;
    int ret;

    xmlSecAssert2(cipher != NULL, -1);
        
    if(!xmlSecTransformCheckId(cipher, xmlSecEncBase64Encode) &&
       !xmlSecTransformCheckId(cipher, xmlSecEncBase64Decode)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncBase64Encode,xmlSecEncBase64Decode");
	return(-1);
    }    
    ctx = (xmlSecBase64CtxPtr)cipher->data;
    
    ret = xmlSecBase64CtxFinal(ctx, cipher->bufOut, cipher->id->bufOutSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    " ");
	return(-1);
    }
    return(ret);
}



/************************************************************************
 *
 * Base64 Context
 *
 ***********************************************************************/

/**
 * xmlSecBase64CtxEncode:
 */
static int
xmlSecBase64CtxEncode(xmlSecBase64CtxPtr ctx) {
    int outPos = 0;

    xmlSecAssert2(ctx != NULL, -1);    

    if(ctx->inPos == 0) {
	return(0); /* nothing to encode */
    }

    outPos = 0;    
    if(ctx->columns > 0 && ctx->columns <= ctx->linePos) {
	ctx->out[outPos++] = '\n';
	ctx->linePos = 0;
    }
    ctx->out[outPos++] = xmlSecBase64Encode1(ctx->in[0]);
    ++(ctx->linePos);

    if(ctx->columns > 0 && ctx->columns <= ctx->linePos) {
	ctx->out[outPos++] = '\n';
	ctx->linePos = 0;
    }
    ++(ctx->linePos);
    ctx->out[outPos++] = xmlSecBase64Encode2(ctx->in[0], ctx->in[1]);

    if(ctx->columns > 0 && ctx->columns <= ctx->linePos) {
	ctx->out[outPos++] = '\n';
	ctx->linePos = 0;
    }
    ++(ctx->linePos);
    ctx->out[outPos++] = (ctx->inPos > 1) ? xmlSecBase64Encode3(ctx->in[1], ctx->in[2]) : '=';

    if(ctx->columns > 0 && ctx->columns <= ctx->linePos) {
	ctx->out[outPos++] = '\n';
	ctx->linePos = 0;
    }
    ++(ctx->linePos);
    ctx->out[outPos++] = (ctx->inPos > 2) ? xmlSecBase64Encode4(ctx->in[2]) : '=';
    	    
    ctx->inPos = 0;    
    return(outPos);
}

/**
 * xmlSecBase64CtxDecode:
 */
static int
xmlSecBase64CtxDecode(xmlSecBase64CtxPtr ctx) {
    int outPos;
    
    xmlSecAssert2(ctx != NULL, -1);
    
    outPos = 0;
    if(ctx->inPos == 0) {
	return(0); /* nothing to decode */
    }
    if(ctx->inPos < 2) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "only one or two equal signs are allowed at the end");
	return(-1);
    }
    ctx->out[outPos++] = xmlSecBase64Decode1(ctx->in[0], ctx->in[1]);

    if(ctx->inPos > 2) {
	ctx->out[outPos++] = xmlSecBase64Decode2(ctx->in[1], ctx->in[2]);
	if(ctx->inPos > 3) {
	    ctx->out[outPos++] = xmlSecBase64Decode3(ctx->in[2], ctx->in[3]);
	}
    }
    ctx->inPos = 0;
    return(outPos);
}

/**
 * xmlSecBase64CtxCreate:
 * @encode: the encode/decode flag (1 - encode, 0 - decode) 
 * @columns: the max line length.
 *
 * Creates new base64 context.
 *
 * Returns a pointer to newly created #xmlSecBase64Ctx structure
 * or NULL if an error occurs.
 */
xmlSecBase64CtxPtr	
xmlSecBase64CtxCreate(int encode, int columns) {
    xmlSecBase64CtxPtr ctx;
    
    /*
     * Allocate a new xmlSecBase64CtxPtr and fill the fields.
     */
    ctx = (xmlSecBase64CtxPtr) xmlMalloc(sizeof(xmlSecBase64Ctx));
    if (ctx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecBase64Ctx)=%d", 
		    sizeof(xmlSecBase64Ctx));
	return(NULL);
    }
    memset(ctx, 0, sizeof(xmlSecBase64Ctx));

    ctx->linePos = 0;
    ctx->encode = encode;
    ctx->columns = columns;
    return(ctx);
}

/**
 * xmlSecBase64CtxDestroy:
 * @ctx: the pointer to #xmlSecBase64Ctx structure.
 * 
 * Destroys base64 context.
 */
void
xmlSecBase64CtxDestroy(xmlSecBase64CtxPtr ctx) {

    xmlSecAssert(ctx != NULL);
    
    memset(ctx, 0, sizeof(xmlSecBase64Ctx)); 
    xmlFree(ctx);
}

/**
 * xmlSecBase64CtxUpdate:
 * @ctx: the pointer to #xmlSecBase64Ctx structure
 * @in:	the input buffer
 * @inLen: the input buffer size
 * @out: the output buffer
 * @outLen: the output buffer size
 *
 * Encodes/decodes the next piece of data from input buffer.
 * 
 * Returns the number of bytes written to output buffer or 
 * -1 if an error occurs.
 */
int
xmlSecBase64CtxUpdate(xmlSecBase64CtxPtr ctx,
		     const unsigned char *in, size_t inLen, 
		     unsigned char *out, size_t outLen) {
    unsigned char ch;
    size_t inPos, outPos;
    size_t size;
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outLen > 0, -1);
    
    if((in == NULL) || (inLen == 0)) {
	return(0);
    }    
        
    inPos = outPos = 0;
    size = (ctx->encode) ? 3 : 4;
    
    /* if we have something in in process this first */
    while(inPos < inLen) {
	if(ctx->inPos >= size) {
	    /* do encode/decode */
	    if(ctx->encode) {
		ret = xmlSecBase64CtxEncode(ctx);
	    } else {
		ret = xmlSecBase64CtxDecode(ctx);
	    }
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    (ctx->encode) ? "xmlSecBase64CtxEncode" : "xmlSecBase64CtxDecode");
		return(-1);
	    }
	    
	    if(outPos + ret > outLen) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_INVALID_DATA,
			    "buffer is too small (%d > %d)", 
			    outPos + ret, outLen); 
		return(-1);
	    }	    
	    memcpy(out + outPos, ctx->out, ret);
	    outPos += ret;
	}
	
	/* read next char in the buffer */
	ch = in[inPos++];
	if(ctx->encode) {
	    ctx->in[ctx->inPos++] = ch;
	} else if(xmlSecIsBase64Char(ch)) {
	    if(ctx->equalSigns != 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_INVALID_DATA,
			    "only space characters are allowed after equal sign \'=\'");
		return(-1);    
	    }
	    if((ch >= 'A') && (ch <= 'Z')) {
		ctx->in[ctx->inPos++] = (ch - 'A');
	    } else if((ch >= 'a') && (ch <= 'z')) {
		ctx->in[ctx->inPos++] = 26 + (ch - 'a');
	    } else if((ch >= '0') && (ch <= '9')) {
		ctx->in[ctx->inPos++] = 52 + (ch - '0'); 
	    } else if(ch == '+') {
		ctx->in[ctx->inPos++] = 62;
	    } else if(ch == '/') {
		ctx->in[ctx->inPos++] = 63;
	    }	    
	} else if(ch == '='){
	    if(ctx->equalSigns >= 2) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_INVALID_DATA,
			    "too many equal signs at the end (most of two accepted)");
		return(-1);    
	    }
	    ++ctx->equalSigns;
	}
    }
        
    return(outPos);
}

/**
 * xmlSecBase64CtxFinal:
 * @ctx: the pointer to #xmlSecBase64Ctx structure
 * @out: the output buffer
 * @outLen: the output buffer size
 *
 * Encodes/decodes the last piece of data stored in the context
 * and finalizes the result.
 *
 * Returns the number of bytes written to output buffer or 
 * -1 if an error occurs.
 */
int
xmlSecBase64CtxFinal(xmlSecBase64CtxPtr ctx, 
		    unsigned char *out, size_t outLen) {
    int ret;
    size_t size;
        
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(out != NULL, -1);    
    xmlSecAssert2(outLen > 0, -1);    

    /* zero uninitialized input bytes */
    size = (ctx->encode) ? 3 : 4;
    memset(ctx->in + ctx->inPos, 0, size - ctx->inPos);

    /* do encode/decode */
    if(ctx->encode) {
	ret = xmlSecBase64CtxEncode(ctx);
    } else {
	ret = xmlSecBase64CtxDecode(ctx);
    }
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    (ctx->encode) ? "xmlSecBase64CtxEncode" : "xmlSecBase64CtxDecode");
	return(-1);
    }
	    
    /* copy to out put buffer */
    if((size_t)ret > outLen) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "buffer is too small (%d > %d)", 
		    ret, outLen); 
	return(-1);
    }	    
    if(ret > 0) {
	memcpy(out, ctx->out, ret);
    }    
#if 0
    /* add \n at the end of decoding (todo: do we need it?) */
    if(ctx->encode && (ctx->columns > 0) && ((ret + 1) < outLen)) {
	out[ret++] = '\n';
    }
#endif    
    /* add \0 */
    if((size_t)(ret + 1) < outLen) {
	out[ret] = '\0';
    }
    return(ret);
}

/**
 * xmlSecBase64Encode:
 * @buf: the input buffer.
 * @len: the input buffer size.
 * @columns: the output max line length (if 0 then no line breaks
 *           would be inserted)
 *
 * Encodes the data from input buffer and allocates the string for the result.
 * The caller is responsible for freeing returned buffer using
 * xmlFree() function.
 *
 * Returns newly allocated string with base64 encoded data 
 * or NULL if an error occurs.
 */
xmlChar*
xmlSecBase64Encode(const unsigned char *buf, size_t len, int columns) {
    xmlSecBase64CtxPtr ctx;
    xmlChar *ptr;
    size_t size;    
    int size_update, size_final;
    int ret;

    xmlSecAssert2(buf != NULL, NULL);

    ctx = xmlSecBase64CtxCreate(1, columns);
    if(ctx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64CtxCreate");
	return(NULL);
    }
    
    /* create result buffer */
    size = (4 * len) / 3 + 4;
    if(columns > 0) {
	size += (size / columns) + 4;
    }
    ptr = (xmlChar*) xmlMalloc(size);
    if(ptr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", size);
	xmlSecBase64CtxDestroy(ctx);
	return(NULL);
    }

    ret = xmlSecBase64CtxUpdate(ctx, buf, len, (unsigned char*)ptr, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64CtxUpdate");
	xmlFree(ptr);
	xmlSecBase64CtxDestroy(ctx);
	return(NULL);
    }
    size_update = ret;

    ret = xmlSecBase64CtxFinal(ctx, ((unsigned char*)ptr) + size_update, size - size_update);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64CtxFinal");
	xmlFree(ptr);
	xmlSecBase64CtxDestroy(ctx);
	return(NULL);
    }
    size_final = ret;
    ptr[size_update + size_final] = '\0';
    
    xmlSecBase64CtxDestroy(ctx);
    return(ptr);
}

/**
 * xmlSecBase64Decode:
 * @str: the input buffer with base64 encoded string
 * @buf: the output buffer
 * @len: the output buffer size
 *
 * Decodes input base64 encoded string and puts result into
 * the output buffer.
 *
 * Returns the number of bytes written to the output buffer or 
 * a negative value if an error occurs 
 */
int
xmlSecBase64Decode(const xmlChar* str, unsigned char *buf, size_t len) {
    xmlSecBase64CtxPtr ctx;
    int size_update;
    int size_final;
    int ret;

    xmlSecAssert2(str != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    
    ctx = xmlSecBase64CtxCreate(0, 0);
    if(ctx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64CtxCreate");
	return(-1);
    }
    
    ret = xmlSecBase64CtxUpdate(ctx, (const unsigned char*)str, xmlStrlen(str), buf, len);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64CtxUpdate");
	xmlSecBase64CtxDestroy(ctx);
	return(-1);
    }

    size_update = ret;
    ret = xmlSecBase64CtxFinal(ctx, buf + size_update, len - size_update);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64CtxFinal");
	xmlSecBase64CtxDestroy(ctx);
	return(-1);
    }
    size_final = ret;    

    xmlSecBase64CtxDestroy(ctx);
    return(size_update + size_final);
}

