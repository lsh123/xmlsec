/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Base64 encode/decode transform and utility functions.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
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

#define xmlSecBase64Min(a, b)		(((a) < (b)) ? (a) : (b))
#define xmlSecBase64Encode1(a) 		(base64[(((a) >> 2) & 0x3F)])
#define xmlSecBase64Encode2(a, b) 	(base64[((((a) << 4) & 0x30) | (((b) >> 4) & 0x0F))])
#define xmlSecBase64Encode3(b, c) 	(base64[((((b) << 2) & 0x3c) | (((c) >> 6) & 0x03))])
#define xmlSecBase64Encode4(c)		(base64[((c) & 0x3F)])

#define xmlSecBase64Decode1(a, b)	(((a) << 2) | (((b) & 0x3F) >> 4))
#define xmlSecBase64Decode2(b, c)	(((b) << 4) | (((c) & 0x3F) >> 2))
#define xmlSecBase64Decode3(c, d)	(((c) << 6) | ((d) & 0x3F))
	
#define xmlSecIsBase64Char(ch) 		((((ch) >= 'A') && ((ch) <= 'Z')) || \
					 (((ch) >= 'a') && ((ch) <= 'z')) || \
					 (((ch) >= '0') && ((ch) <= '9')) || \
					  ((ch) == '+') || ((ch) == '/')) 
#define xmlSecIsBase64Space(ch)		(((ch) == ' ') || ((ch) == '\t') || \
					 ((ch) == '\x0d') || ((ch) == '\x0a'))

/***********************************************************************
 *
 * Base64 Context
 *
 ***********************************************************************/
struct _xmlSecBase64Ctx {
    int			encode;
    
    unsigned int	in[4];
    unsigned char	out[16];
    size_t 		inPos;
    size_t 		outPos;
    
    size_t		linePos;
    size_t		columns;    
    int			equalSigns;
};


static int		xmlSecBase64CtxEncode		(xmlSecBase64CtxPtr ctx);
static int		xmlSecBase64CtxDecode		(xmlSecBase64CtxPtr ctx);
static int		xmlSecBase64CtxPush		(xmlSecBase64CtxPtr ctx,
							 const unsigned char* in,
							 size_t inSize);
static int		xmlSecBase64CtxPop		(xmlSecBase64CtxPtr ctx,
							 unsigned char* out,
							 size_t outSize,
							 int final);
/************************************************************************
 *
 * Base64 Context
 *
 ***********************************************************************/
static int
xmlSecBase64CtxEncode(xmlSecBase64CtxPtr ctx) {
    xmlSecAssert2(ctx != NULL, -1);    
    xmlSecAssert2(ctx->inPos <= sizeof(ctx->in) / sizeof(ctx->in[0]), -1);
    xmlSecAssert2(ctx->outPos <= sizeof(ctx->out) / sizeof(ctx->out[0]), -1);

    if(ctx->outPos > 0) {
	return(ctx->outPos);
    } else if(ctx->inPos == 0) {
	return(0); /* nothing to encode */
    }

    if(ctx->columns > 0 && ctx->columns <= ctx->linePos) {
	ctx->out[ctx->outPos++] = '\n';
	ctx->linePos = 0;
    }
    ++(ctx->linePos);
    ctx->out[ctx->outPos++] = xmlSecBase64Encode1(ctx->in[0]);

    if(ctx->columns > 0 && ctx->columns <= ctx->linePos) {
	ctx->out[ctx->outPos++] = '\n';
	ctx->linePos = 0;
    }
    ++(ctx->linePos);
    if(ctx->inPos > 1) {
        ctx->out[ctx->outPos++] = xmlSecBase64Encode2(ctx->in[0], ctx->in[1]);
    } else {
        ctx->out[ctx->outPos++] = xmlSecBase64Encode2(ctx->in[0], 0);
    }

    if(ctx->columns > 0 && ctx->columns <= ctx->linePos) {
	ctx->out[ctx->outPos++] = '\n';
	ctx->linePos = 0;
    }
    ++(ctx->linePos);
    if(ctx->inPos > 1) {
	if(ctx->inPos > 2) {
    	    ctx->out[ctx->outPos++] = xmlSecBase64Encode3(ctx->in[1], ctx->in[2]);
	} else {
    	    ctx->out[ctx->outPos++] = xmlSecBase64Encode3(ctx->in[1], 0);
	}
    } else {
        ctx->out[ctx->outPos++] = '=';
    }
    
    if(ctx->columns > 0 && ctx->columns <= ctx->linePos) {
	ctx->out[ctx->outPos++] = '\n';
	ctx->linePos = 0;
    }
    ++(ctx->linePos);
    if(ctx->inPos > 2) {
	ctx->out[ctx->outPos++] = xmlSecBase64Encode4(ctx->in[2]);
    } else {
        ctx->out[ctx->outPos++] = '=';
    }
    	    
    ctx->inPos = 0;    
    return(ctx->outPos);
}

static int
xmlSecBase64CtxDecode(xmlSecBase64CtxPtr ctx) {    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->inPos <= sizeof(ctx->in) / sizeof(ctx->in[0]), -1);
    xmlSecAssert2(ctx->outPos <= sizeof(ctx->out) / sizeof(ctx->out[0]), -1);

    if(ctx->outPos > 0) {
	return(ctx->outPos);
    } else if(ctx->inPos == 0) {
	return(0); /* nothing to encode */
    }

    if(ctx->inPos < 2) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecBase64Ctx",
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "only one or two equal signs are allowed at the end");
	return(-1);
    }
    ctx->out[ctx->outPos++] = xmlSecBase64Decode1(ctx->in[0], ctx->in[1]);

    if(ctx->inPos > 2) {
	ctx->out[ctx->outPos++] = xmlSecBase64Decode2(ctx->in[1], ctx->in[2]);
	if(ctx->inPos > 3) {
	    ctx->out[ctx->outPos++] = xmlSecBase64Decode3(ctx->in[2], ctx->in[3]);
	}
    }
    ctx->inPos = 0;
    return(ctx->outPos);
}

static int 
xmlSecBase64CtxPush(xmlSecBase64CtxPtr ctx, const unsigned char* in, size_t inSize) {
    size_t inBlockSize;
    size_t i;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->inPos <= sizeof(ctx->in) / sizeof(ctx->in[0]), -1);
    xmlSecAssert2(ctx->outPos <= sizeof(ctx->out) / sizeof(ctx->out[0]), -1);
    xmlSecAssert2(in != NULL, -1);
    
    inBlockSize = (ctx->encode) ? 3 : 4;
    if(ctx->encode) {
	if((ctx->inPos < inBlockSize) && (inSize > 0)) {
	    inBlockSize = xmlSecBase64Min(inSize, (inBlockSize - ctx->inPos));
	    for(i = 0; i < inBlockSize; ++i) {
		ctx->in[i + ctx->inPos] = in[i];
	    }
	    ctx->inPos += inBlockSize;
	    return(inBlockSize);
	}
    } else {
	unsigned char ch;
        size_t inPos;
	
	for(inPos = 0; (inPos < inSize) && (ctx->inPos < sizeof(ctx->in) / sizeof(ctx->in[0])); ++inPos) {
	    ch = in[inPos];
	    if(ctx->equalSigns > 0) {
		if((ch == '=') && (ctx->equalSigns < 2)) {
		    ++ctx->equalSigns;
		} else if(!xmlSecIsBase64Space(ch)) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				"xmlSecBase64Ctx",
				NULL,
				XMLSEC_ERRORS_R_INVALID_DATA,
				"too many equal signs at the end or non space character after equal sign");
		    return(-1);    
		}
	    } else if(ch == '=') {
		++ctx->equalSigns;
	    } else if(xmlSecIsBase64Char(ch)) {
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
	    } else if(!xmlSecIsBase64Space(ch)) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    "xmlSecBase64Ctx",
			    NULL,
			    XMLSEC_ERRORS_R_INVALID_DATA,
			    "non-base64 and non-space character \'%c\'", ch);
		return(-1);    
	    }
	}
	
	return(inPos);
    }
    return(0);
}

static int 
xmlSecBase64CtxPop(xmlSecBase64CtxPtr ctx, unsigned char* out, size_t outSize, int final) {
    size_t inBlockSize;    
    size_t outBlockSize;    
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->inPos <= sizeof(ctx->in) / sizeof(ctx->in[0]), -1);
    xmlSecAssert2(ctx->outPos <= sizeof(ctx->out) / sizeof(ctx->out[0]), -1);
    xmlSecAssert2(out != NULL, -1);

    inBlockSize = (ctx->encode) ? 3 : 4;
    if((ctx->outPos == 0) && ((ctx->inPos >= inBlockSize) || final)) {
	/* do encode/decode */
	if(ctx->encode) {
	    ret = xmlSecBase64CtxEncode(ctx);
	} else {
	    ret = xmlSecBase64CtxDecode(ctx);
	}
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			"xmlSecBase64Ctx",
			(ctx->encode) ? "xmlSecBase64CtxEncode" : "xmlSecBase64CtxDecode",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }
    
    outBlockSize = xmlSecBase64Min(ctx->outPos, outSize);
    if(outBlockSize > 0) {
	memcpy(out, ctx->out, outBlockSize);
	if(outBlockSize < ctx->outPos) {
    	    memmove(ctx->out, ctx->out + outBlockSize, ctx->outPos - outBlockSize);
	}
	ctx->outPos -= outBlockSize;
    }
    return(outBlockSize);
}

/**
 * xmlSecBase64CtxCreate:
 * @encode:		the encode/decode flag (1 - encode, 0 - decode) 
 * @columns: 		the max line length.
 *
 * Allocates and initializes new base64 context.
 *
 * Returns a pointer to newly created #xmlSecBase64Ctx structure
 * or NULL if an error occurs.
 */
xmlSecBase64CtxPtr	
xmlSecBase64CtxCreate(int encode, int columns) {
    xmlSecBase64CtxPtr ctx;
    int ret;
    
    /*
     * Allocate a new xmlSecBase64CtxPtr and fill the fields.
     */
    ctx = (xmlSecBase64CtxPtr) xmlMalloc(sizeof(xmlSecBase64Ctx));
    if (ctx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecBase64Ctx",
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecBase64Ctx)=%d", 
		    sizeof(xmlSecBase64Ctx));
	return(NULL);
    }
    
    ret = xmlSecBase64CtxInitialize(ctx, encode, columns);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBase64CtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecBase64CtxDestroy(ctx);
	return(NULL);
    }
    return(ctx);
}

/**
 * xmlSecBase64CtxDestroy:
 * @ctx: 		the pointer to #xmlSecBase64Ctx structure.
 * 
 * Destroys base64 context.
 */
void
xmlSecBase64CtxDestroy(xmlSecBase64CtxPtr ctx) {
    xmlSecAssert(ctx != NULL);
    
    xmlSecBase64CtxFinalize(ctx);
    xmlFree(ctx);
}

/**
 * xmlSecBase64CtxInitialize:
 * @ctx:		the pointer to #xmlSecBase64Ctx structure,
 * @encode:		the encode/decode flag (1 - encode, 0 - decode) 
 * @columns: 		the max line length.
 *
 * Initializes new base64 context.
 *
 * Returns 0 on success and a negative value otherwise.
 */
int 
xmlSecBase64CtxInitialize(xmlSecBase64CtxPtr ctx, int encode, int columns) {
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecBase64Ctx));

    ctx->linePos = 0;
    ctx->encode = encode;
    ctx->columns = columns;

    return(0);
}

/**
 * xmlSecBase64CtxFinalize:
 * @ctx:		the pointer to #xmlSecBase64Ctx structure,
 *
 * Frees all the resources allocated by @ctx.
 */
void 
xmlSecBase64CtxFinalize(xmlSecBase64CtxPtr ctx) {
    xmlSecAssert(ctx != NULL);
    
    memset(ctx, 0, sizeof(xmlSecBase64Ctx)); 
}	

/**
 * xmlSecBase64CtxUpdate:
 * @ctx: 		the pointer to #xmlSecBase64Ctx structure
 * @in:			the input buffer
 * @inSize: 		the input buffer size
 * @out: 		the output buffer
 * @outSize: 		the output buffer size
 *
 * Encodes or decodes the next piece of data from input buffer.
 * 
 * Returns the number of bytes written to output buffer or 
 * -1 if an error occurs.
 */
int
xmlSecBase64CtxUpdate(xmlSecBase64CtxPtr ctx,
		     const unsigned char *in, size_t inSize, 
		     unsigned char *out, size_t outSize) {
    int res = 0;
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);


    while((inSize > 0) && (outSize > 0)) {	    
	ret = xmlSecBase64CtxPush(ctx, in, inSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			"xmlSecBase64Ctx",
			"xmlSecBase64CtxPush",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"%d", inSize);
	    return(-1);
	}
	xmlSecAssert2((size_t)ret <= inSize, -1);
	in += ret;
	inSize -= ret;

	ret = xmlSecBase64CtxPop(ctx, out, outSize, 0);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			"xmlSecBase64Ctx",
			"xmlSecBase64CtxPop",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", outSize);
	    return(-1);
	} else if(ret == 0) {
	    break;
	}
	xmlSecAssert2((size_t)ret <= outSize, -1);
	out += ret;
	outSize -= ret;
	res += ret;
    }

    return(res);
}

/**
 * xmlSecBase64CtxFinal:
 * @ctx: 		the pointer to #xmlSecBase64Ctx structure
 * @out: 		the output buffer
 * @outSize: 		the output buffer size
 *
 * Encodes or decodes the last piece of data stored in the context
 * and finalizes the result.
 *
 * Returns the number of bytes written to output buffer or 
 * -1 if an error occurs.
 */
int
xmlSecBase64CtxFinal(xmlSecBase64CtxPtr ctx, 
		    unsigned char *out, size_t outSize) {
    size_t outPos;
    int ret;
        
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(out != NULL, -1);    
    xmlSecAssert2(outSize > 0, -1);    

    for(outPos = 0; (outPos < outSize); ) {
	ret = xmlSecBase64CtxPop(ctx, out + outPos, outSize - outPos, 1);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			"xmlSecBase64Ctx",
			"xmlSecBase64CtxPop",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"%d", outSize - outPos);
	    return(-1);
	} else if(ret == 0) {
	    break;
	}
	outPos += ret;
    }
	    
    /* copy to out put buffer */
    if(outPos >= outSize) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecBase64Ctx",
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "buffer is too small (%d > %d)", 
		    outPos, outSize); 
	return(-1);
    }	    

    /* add \0 */
    if((outPos + 1) < outSize) {
	out[outPos] = '\0';
    }
    return(outPos);
}

/**
 * xmlSecBase64Encode:
 * @buf: 		the input buffer.
 * @len: 		the input buffer size.
 * @columns: 		the output max line length (if 0 then no line breaks
 *          		would be inserted)
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
		    NULL,
		    "xmlSecBase64CtxCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
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
		    NULL,
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", size);
	xmlSecBase64CtxDestroy(ctx);
	return(NULL);
    }

    ret = xmlSecBase64CtxUpdate(ctx, buf, len, (unsigned char*)ptr, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBase64CtxUpdate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%d", len);
	xmlFree(ptr);
	xmlSecBase64CtxDestroy(ctx);
	return(NULL);
    }
    size_update = ret;

    ret = xmlSecBase64CtxFinal(ctx, ((unsigned char*)ptr) + size_update, size - size_update);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBase64CtxFinal",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
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
 * @str: 		the input buffer with base64 encoded string
 * @buf: 		the output buffer
 * @len: 		the output buffer size
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
		    NULL,
		    "xmlSecBase64CtxCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    ret = xmlSecBase64CtxUpdate(ctx, (const unsigned char*)str, xmlStrlen(str), buf, len);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBase64CtxUpdate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecBase64CtxDestroy(ctx);
	return(-1);
    }

    size_update = ret;
    ret = xmlSecBase64CtxFinal(ctx, buf + size_update, len - size_update);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBase64CtxFinal",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecBase64CtxDestroy(ctx);
	return(-1);
    }
    size_final = ret;    

    xmlSecBase64CtxDestroy(ctx);
    return(size_update + size_final);
}

/**************************************************************
 *
 * Base64 Transform
 *
 * xmlSecBase64Ctx is located after xmlSecTransform
 * 
 **************************************************************/
#define xmlSecBase64Size \
	(sizeof(xmlSecTransform) + sizeof(xmlSecBase64Ctx))
#define xmlSecBase64GetCtx(transform) \
    ((xmlSecTransformCheckSize((transform), xmlSecBase64Size)) ? \
	(xmlSecBase64CtxPtr)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)) : \
	(xmlSecBase64CtxPtr)NULL)

static int		xmlSecBase64Initialize		(xmlSecTransformPtr transform);
static void		xmlSecBase64Finalize		(xmlSecTransformPtr transform);
static int 		xmlSecBase64Execute		(xmlSecTransformPtr transform, 
							 int last, 
							 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecBase64Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecBase64Size,				/* size_t objSize */

    xmlSecNameBase64,				/* const xmlChar* name; */
    xmlSecHrefBase64,				/* const xmlChar* href; */
    xmlSecTransformUsageDSigTransform,		/* xmlSecAlgorithmUsage usage; */

    xmlSecBase64Initialize, 			/* xmlSecTransformInitializeMethod initialize; */
    xmlSecBase64Finalize,			/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecBase64Execute,			/* xmlSecTransformExecuteMethod execute; */

    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecTransformBase64GetKlass:
 *
 * The Base64 transform klass (http://www.w3.org/TR/xmldsig-core/#sec-Base-64).
 * The normative specification for base64 decoding transforms is RFC 2045
 * (http://www.ietf.org/rfc/rfc2045.txt). The base64 Transform element has 
 * no content. The input is decoded by the algorithms. This transform is 
 * useful if an application needs to sign the raw data associated with 
 * the encoded content of an element.
 *
 * Returns base64 transform id.
 */
xmlSecTransformId 
xmlSecTransformBase64GetKlass(void) {
    return(&xmlSecBase64Klass);
}

/**
 * xmlSecTransformBase64SetLineSize:
 * @transform: 		the pointer to BASE64 encode transform.
 * @lineSize: 		the new max line size.
 *
 * Sets the max line size to @lineSize.
 */
void
xmlSecTransformBase64SetLineSize(xmlSecTransformPtr transform, size_t lineSize) {
    xmlSecBase64CtxPtr ctx;
    
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecTransformBase64Id));
    
    ctx = xmlSecBase64GetCtx(transform);
    xmlSecAssert(ctx != NULL);
    
    ctx->columns = lineSize;    
}

static int
xmlSecBase64Initialize(xmlSecTransformPtr transform) {
    xmlSecBase64CtxPtr ctx;
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformBase64Id), -1);

    ctx = xmlSecBase64GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    transform->operation = xmlSecTransformOperationDecode;
    ret = xmlSecBase64CtxInitialize(ctx, 0, XMLSEC_BASE64_LINESIZE);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBase64CtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    return(0);
}

static void
xmlSecBase64Finalize(xmlSecTransformPtr transform) {
    xmlSecBase64CtxPtr ctx;
    
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecTransformBase64Id));

    ctx = xmlSecBase64GetCtx(transform);
    xmlSecAssert(ctx != NULL);
    
    xmlSecBase64CtxFinalize(ctx);
}

static int 
xmlSecBase64Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBase64CtxPtr ctx;
    xmlSecBufferPtr in, out;
    size_t inLen, outLen;
    unsigned char buf[3 * XMLSEC_TRANSFORM_BINARY_CHUNK];
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformBase64Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncode) || (transform->operation == xmlSecTransformOperationDecode), -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    
    ctx = xmlSecBase64GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    
    in = &(transform->inBuf);
    out = &(transform->outBuf);

    if(transform->status == xmlSecTransformStatusNone) {
	ctx->encode = (transform->operation == xmlSecTransformOperationEncode) ? 1 : 0;
	transform->status = xmlSecTransformStatusWorking;
    }

    switch(transform->status) {
	case xmlSecTransformStatusWorking:
	    while(xmlSecBufferGetSize(in) > 0) {
		/* find next chunk size */
		inLen = xmlSecBufferGetSize(in);
		if(inLen > XMLSEC_TRANSFORM_BINARY_CHUNK) {
		    inLen = XMLSEC_TRANSFORM_BINARY_CHUNK;
		}
		
		/* encode/decode the next chunk */
		ret = xmlSecBase64CtxUpdate(ctx, xmlSecBufferGetData(in), inLen,
					    buf, sizeof(buf));
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"xmlSecBase64CtxUpdate",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				XMLSEC_ERRORS_NO_MESSAGE);
		    return(-1);
		}
		outLen = ret;
		
		/* add encoded chunk to output */
		ret = xmlSecBufferAppend(out, buf, outLen);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"xmlSecBufferAppend",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"%d", outLen);
		    return(-1);
		}
		
		/* remove chunk from input */
		ret = xmlSecBufferRemoveHead(in, inLen);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"xmlSecBufferRemoveHead",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"%d", inLen);
		    return(-1);
		}
	    }
	    
	    if(last) {
		/* add from ctx buffer */
		ret = xmlSecBase64CtxFinal(ctx, buf, sizeof(buf));
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"xmlSecBase64CtxFinal",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				XMLSEC_ERRORS_NO_MESSAGE);
		    return(-1);
		}
		outLen = ret;
		
		/* add encoded chunk to output */
		ret = xmlSecBufferAppend(out, buf, outLen);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"xmlSecBufferAppend",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"%d", outLen);
		    return(-1);
		}
		transform->status = xmlSecTransformStatusFinished;
	    }
	    break;
	case xmlSecTransformStatusFinished:
	    /* the only way we can get here is if there is no input */
	    xmlSecAssert2(xmlSecBufferGetSize(in) == 0, -1);
	    break;
	default:
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			NULL,
			XMLSEC_ERRORS_R_INVALID_STATUS,
			"%d", transform->status);
	    return(-1);
    }
    return(0);
}

