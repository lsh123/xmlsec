/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Internal header only used during the compilation,
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */

#ifndef __XMLSEC_ERROR_HELPERS_H__
#define __XMLSEC_ERROR_HELPERS_H__

#ifndef XMLSEC_PRIVATE
#error "private.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */

#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**********************************************************************
 *
 * Error handling macros.
 *
 **********************************************************************/

/**
 * xmlSecInternalError:
 * @errorFunction:      the failed function name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting internal XMLSec errors.
 */
#define xmlSecInternalError(errorFunction, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,          \
                    XMLSEC_ERRORS_NO_MESSAGE                \
        )

/**
 * xmlSecInternalError2:
 * @errorFunction:      the failed function name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @msg:                the extra message.
 * @param:              the extra message param.
 *
 * Macro. The XMLSec library macro for reporting internal XMLSec errors.
 */
#define xmlSecInternalError2(errorFunction, errorObject, msg, param) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,          \
                    (msg), (param)                          \
        )

/**
 * xmlSecInternalError3:
 * @errorFunction:      the failed function name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @msg:                the extra message.
 * @param1:             the extra message param1.
 * @param2:             the extra message param2.
 *
 * Macro. The XMLSec library macro for reporting internal XMLSec errors.
 */
#define xmlSecInternalError3(errorFunction, errorObject, msg, param1, param2) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,          \
                    (msg), (param1), (param2)               \
        )

/**
 * xmlSecInternalError4:
 * @errorFunction:      the failed function name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @msg:                the extra message.
 * @param1:             the extra message param1.
 * @param2:             the extra message param2.
 * @param3:             the extra message param3.
 *
 * Macro. The XMLSec library macro for reporting internal XMLSec errors.
 */
#define xmlSecInternalError4(errorFunction, errorObject, msg, param1, param2, param3) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,          \
                    (msg), (param1), (param2), (param3)     \
        )

/**
 * xmlSecMallocError:
 * @allocSize:          the failed allocation size.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting xmlMalloc() errors.
 */
#define xmlSecMallocError(allocSize, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    "xmlMalloc",                            \
                    XMLSEC_ERRORS_R_MALLOC_FAILED,          \
                    "size=%lu", (unsigned long)(allocSize)  \
        )

/**
 * xmlSecStrdupError:
 * @str:                the failed string.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting xmlStrdup() errors.
 */
#define xmlSecStrdupError(str, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    "xmlStrdup",                            \
                    XMLSEC_ERRORS_R_STRDUP_FAILED,          \
                    "size=%lu", (unsigned long)xmlStrlen(str) \
        )

/**
 * xmlSecXmlError:
 * @errorFunction:      the failed function.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting generic XML errors.
 */
#define xmlSecXmlError(errorFunction, errorObject) \
    {                                                 \
        xmlErrorPtr error = xmlGetLastError();        \
        int code = (error != NULL) ? error->code : 0; \
        const char* message = (error != NULL) ? error->message : NULL; \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   (errorFunction),                   \
                   XMLSEC_ERRORS_R_XML_FAILED,        \
                   "xml error: %lu: %s",              \
                   (unsigned long)code,               \
                   xmlSecErrorsSafeString(message)    \
        );                                            \
    }

/**
 * xmlSecXmlError2:
 * @errorFunction:      the failed function.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @msg:                the extra message.
 * @param:              the extra message param.
 *
 * Macro. The XMLSec library macro for reporting generic XML errors.
 */
#define xmlSecXmlError2(errorFunction, errorObject, msg, param) \
    {                                                 \
        xmlErrorPtr error = xmlGetLastError();        \
        int code = (error != NULL) ? error->code : 0; \
        const char* message = (error != NULL) ? error->message : NULL; \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   (errorFunction),                   \
                   XMLSEC_ERRORS_R_XML_FAILED,        \
                   msg "; xml error: %lu: %s",        \
                   (param),                           \
                   (unsigned long)code,               \
                   xmlSecErrorsSafeString(message)    \
        );                                            \
    }

/**
 * xmlSecXmlParserError:
 * @errorFunction:      the failed function.
 * @ctxt:               the parser context.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting XML parser errors.
 */
#define xmlSecXmlParserError(errorFunction, ctxt, errorObject) \
    {                                                 \
        xmlErrorPtr error = xmlCtxtGetLastError(ctxt);\
        int code = (error != NULL) ? error->code : 0; \
        const char* message = (error != NULL) ? error->message : NULL; \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   (errorFunction),                   \
                   XMLSEC_ERRORS_R_XML_FAILED,        \
                   "xml error: %lu: %s",              \
                   (unsigned long)code,               \
                   xmlSecErrorsSafeString(message)    \
        );                                            \
    }

/**
 * xmlSecXmlParserError2:
 * @errorFunction:      the failed function.
 * @ctxt:               the parser context.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @msg:                the extra message.
 * @param:              the extra message param.
 *
 * Macro. The XMLSec library macro for reporting XML parser errors.
 */
#define xmlSecXmlParserError2(errorFunction, ctxt, errorObject, msg, param) \
    {                                                 \
        xmlErrorPtr error = xmlCtxtGetLastError(ctxt);\
        int code = (error != NULL) ? error->code : 0; \
        const char* message = (error != NULL) ? error->message : NULL; \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   (errorFunction),                   \
                   XMLSEC_ERRORS_R_XML_FAILED,        \
                   msg "; xml error: %lu: %s",        \
                   (param),                           \
                   (unsigned long)code,               \
                   xmlSecErrorsSafeString(message)    \
        );                                            \
    }

/**
 * xmlSecXsltError:
 * @errorFunction:      the failed function.
 * @ctxt:               the parser context.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting XSLT errors.
 */
#define xmlSecXsltError(errorFunction, ctxt, errorObject) \
    {                                                 \
        xmlErrorPtr error = xmlGetLastError();        \
        int code = (error != NULL) ? error->code : 0; \
        const char* message = (error != NULL) ? error->message : NULL; \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   (errorFunction),                   \
                   XMLSEC_ERRORS_R_XSLT_FAILED,       \
                   "xslt error: %lu: %s",             \
                   (unsigned long)code,               \
                   xmlSecErrorsSafeString(message)    \
        );                                            \
    }

/**
 * xmlSecIOError:
 * @errorFunction:      the failed function.
 * @name:               the filename, function name, uri, etc.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting IO errors.
 */
#define xmlSecIOError(errorFunction, name, errorObject) \
    {                                                 \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   (errorFunction),                   \
                   XMLSEC_ERRORS_R_IO_FAILED,         \
                   "name=\"%s\"; errno=%d",           \
                   xmlSecErrorsSafeString(name),      \
                   errno                              \
        );                                            \
    }

/**
 * xmlSecNotImplementedError:
 * @details:           the additional details.
 *
 * Macro. The XMLSec library macro for reporting "not implemented" errors.
 */
#define xmlSecNotImplementedError(details) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    NULL,                                   \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,        \
                    "details=%s",                           \
                    xmlSecErrorsSafeString(details)         \
        )
/**
 * xmlSecInvalidSizeError:
 * @name:               the name of the variable, parameter, etc.
 * @actual:             the actual value.
 * @expected:           the expected value.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting "invalid size" errors when
 * we expect exact match.
 */
#define xmlSecInvalidSizeError(name, actual, expected, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    NULL,                                   \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_SIZE,           \
                    "invalid size for '%s': actual=%lu is not equal to expected=%lu", \
                    xmlSecErrorsSafeString(name),           \
                    (unsigned long)(actual),                \
                    (unsigned long)(expected)               \
        )

/**
 * xmlSecInvalidSizeLessThanError:
 * @name:               the name of the variable, parameter, etc.
 * @actual:             the actual value.
 * @expected:           the expected value.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting "invalid size" errors when
 * we expect at least the expected size.
 */
#define xmlSecInvalidSizeLessThanError(name, actual, expected, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    NULL,                                   \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_SIZE,           \
                    "invalid size for '%s': actual=%lu is less than expected=%lu", \
                    xmlSecErrorsSafeString(name),           \
                    (unsigned long)(actual),                \
                    (unsigned long)(expected)               \
        )

/**
 * xmlSecInvalidSizeMoreThanError:
 * @name:               the name of the variable, parameter, etc.
 * @actual:             the actual value.
 * @expected:           the expected value.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting "invalid size" errors when
 * we expect at most the expected size.
 */
#define xmlSecInvalidSizeMoreThanError(name, actual, expected, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    NULL,                                   \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,        \
                    "invalid size for '%s': actual=%lu is more than expected=%lu", \
                    xmlSecErrorsSafeString(name),           \
                    (unsigned long)(actual),                \
                    (unsigned long)(expected)               \
        )

/**
 * xmlSecInvalidSizeNotMultipleOfError:
 * @name:               the name of the variable, parameter, etc.
 * @actual:             the actual value.
 * @divider:            the expected divider.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting "invalid size" errors when
 * we expect the size to be a multiple of the divider.
 */
#define xmlSecInvalidSizeNotMultipleOfError(name, actual, divider, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    NULL,                                   \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,        \
                    "invalid size for '%s': actual=%lu is not a multiple of %lu", \
                    xmlSecErrorsSafeString(name),           \
                    (unsigned long)(actual),                \
                    (unsigned long)(divider)               \
        )

/**
 * xmlSecInvalidNodeError:
 * @actualNode:         the actual node.
 * @expectedNodeName:   the expected node name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting an invalid node errors.
 */
#define xmlSecInvalidNodeError(actualNode, expectedNodeName, errorObject) \
    {                                                 \
        const char* actualNodeName = xmlSecNodeGetName(actualNode); \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   NULL,                              \
                   XMLSEC_ERRORS_R_INVALID_NODE,      \
                   "actual=%s; expected=%s",          \
                   xmlSecErrorsSafeString(actualNodeName),  \
                   xmlSecErrorsSafeString(expectedNodeName) \
        );                                            \
    }

/**
 * xmlSecInvalidNodeContentError:
 * @node:               the node.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @reason:             the reason why node content is invalid.
 *
 * Macro. The XMLSec library macro for reporting an invalid node content errors.
 */
#define xmlSecInvalidNodeContentError(node, errorObject, reason) \
    {                                                 \
        const char* nName = xmlSecNodeGetName(node);  \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   NULL,                              \
                   XMLSEC_ERRORS_R_INVALID_NODE_CONTENT, \
                   "node=%s; reason=%s",              \
                   xmlSecErrorsSafeString(nName),     \
                   xmlSecErrorsSafeString(reason)     \
        );                                            \
    }

/**
 * xmlSecInvalidNodeAttributeError:
 * @node:               the node.
 * @attrName:           the attribute name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @reason:             the reason why node content is invalid.
 *
 * Macro. The XMLSec library macro for reporting an invalid node attribute errors.
 */
#define xmlSecInvalidNodeAttributeError(node, attrName, errorObject, reason) \
    {                                                 \
        const char* nName = xmlSecNodeGetName(node);  \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   NULL,                              \
                   XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE, \
                   "node=%s; attribute=%s; reason=%s",\
                   xmlSecErrorsSafeString(nName),     \
                   xmlSecErrorsSafeString(attrName),  \
                   xmlSecErrorsSafeString(reason)     \
        );                                            \
    }

/**
 * xmlSecNodeAlreadyPresentError:
 * @parent:             the parent node.
 * @nodeName:           the node name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting node already present errors.
 */
#define xmlSecNodeAlreadyPresentError(parent, nodeName, errorObject) \
    {                                                 \
        const char* pName = xmlSecNodeGetName(parent);\
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   NULL,                              \
                   XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT, \
                   "parent=%s; node=%s",              \
                   xmlSecErrorsSafeString(pName),     \
                   xmlSecErrorsSafeString(nodeName)   \
        );                                            \
    }

/**
 * xmlSecUnexpectedNodeError:
 * @node:               the node.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting an invalid node errors.
 */
#define xmlSecUnexpectedNodeError(node, errorObject) \
    {                                                 \
        const char* nName = xmlSecNodeGetName(node);  \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   NULL,                              \
                   XMLSEC_ERRORS_R_UNEXPECTED_NODE,   \
                   "node=%s",                         \
                   xmlSecErrorsSafeString(nName)      \
        );                                            \
    }

/**
 * xmlSecNodeNotFoundError:
 * @errorFunction:      the failed function.
 * @startNode:          the search start node.
 * @targetNodeName:     the expected child node name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting node not found errors.
 */
#define xmlSecNodeNotFoundError(errorFunction, startNode, targetNodeName, errorObject) \
    {                                                 \
        const char* startNodeName = xmlSecNodeGetName(startNode); \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   (errorFunction),                   \
                   XMLSEC_ERRORS_R_NODE_NOT_FOUND,    \
                   "startNode=%s; target=%s",         \
                   xmlSecErrorsSafeString(startNodeName), \
                   xmlSecErrorsSafeString(targetNodeName) \
        );                                            \
    }

/**
 * xmlSecInvalidTransfromError:
 * @transform:          the transform.
 *
 * Macro. The XMLSec library macro for reporting an invalid transform errors.
 */
#define xmlSecInvalidTransfromError(transform) \
    {                                                 \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)xmlSecTransformGetName(transform), \
                   NULL,                              \
                   XMLSEC_ERRORS_R_INVALID_TRANSFORM, \
                   XMLSEC_ERRORS_NO_MESSAGE           \
        );                                            \
    }

/**
 * xmlSecInvalidTransfromError2:
 * @transform:          the transform.
 * @msg:                the extra message.
 * @param:              the extra message param.
 *
 *
 * Macro. The XMLSec library macro for reporting an invalid transform errors.
 */
#define xmlSecInvalidTransfromError2(transform, msg, param) \
    {                                                 \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)xmlSecTransformGetName(transform), \
                   NULL,                              \
                   XMLSEC_ERRORS_R_INVALID_TRANSFORM, \
                   (msg), (param)                     \
        );                                            \
    }

/**
 * xmlSecInvalidTransfromStatusError:
 * @transform:          the transform.
 *
 * Macro. The XMLSec library macro for reporting an invalid transform status errors.
 */
#define xmlSecInvalidTransfromStatusError(transform) \
    {                                                 \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)xmlSecTransformGetName(transform), \
                   NULL,                              \
                   XMLSEC_ERRORS_R_INVALID_STATUS,    \
                   "transformStatus=%d",              \
                   (int)((transform)->status)         \
        );                                            \
    }

/**
 * xmlSecOtherError:
 * @code:               the error code.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @details:            the error message.
 *
 * Macro. The XMLSec library macro for reporting other XMLSec errors.
 */
#define xmlSecOtherError(code, errorObject, details) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    (code),                                 \
                    "details=%s",                           \
                    xmlSecErrorsSafeString(details)         \
        )

/**
 * xmlSecOtherError2:
 * @code:               the error code.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @msg:                the extra message.
 * @param:              the extra message param.
 *
 * Macro. The XMLSec library macro for reporting other XMLSec errors.
 */
#define xmlSecOtherError2(code, errorObject, msg, param) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    (code),                                 \
                    (msg), (param)                          \
        )

/**
 * xmlSecOtherError3:
 * @code:               the error code.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @msg:                the extra message.
 * @param1:             the extra message param.
 * @param2:             the extra message param.
 *
 * Macro. The XMLSec library macro for reporting other XMLSec errors.
 */
#define xmlSecOtherError3(code, errorObject, msg, param1, param2) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    (code),                                 \
                    (msg), (param1), (param2)               \
        )

/**
 * xmlSecOtherError4:
 * @code:               the error code.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @msg:                the extra message.
 * @param1:             the extra message param.
 * @param2:             the extra message param.
 * @param3:             the extra message param.
 *
 * Macro. The XMLSec library macro for reporting other XMLSec errors.
 */
#define xmlSecOtherError4(code, errorObject, msg, param1, param2, param3) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    (code),                                 \
                    (msg), (param1), (param2), (param3)     \
        )

/**
 * xmlSecOtherError5:
 * @code:               the error code.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @msg:                the extra message.
 * @param1:             the extra message param.
 * @param2:             the extra message param.
 * @param3:             the extra message param.
 * @param4:             the extra message param.
 *
 * Macro. The XMLSec library macro for reporting other XMLSec errors.
 */
#define xmlSecOtherError5(code, errorObject, msg, param1, param2, param3, param4) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    (code),                                 \
                    (msg), (param1), (param2), (param3), (param4) \
        )

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_ERROR_HELPERS_H__ */
