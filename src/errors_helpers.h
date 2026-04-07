/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Internal helper macros for error reporting.
 */

#ifndef __XMLSEC_ERROR_HELPERS_H__
#define __XMLSEC_ERROR_HELPERS_H__

#ifndef XMLSEC_PRIVATE
#error "errors_helpers.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */

#include <errno.h>
#include <xmlsec/exports.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/******************************************************************************
 *
 * Error handling macros.
 *
  *****************************************************************************/

/**
 * @brief Macro. Reports internal XMLSec errors.
 * @details Macro. The XMLSec library macro for reporting internal XMLSec errors.
 * @param errorFunction the failed function name.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInternalError(errorFunction, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,          \
                    XMLSEC_ERRORS_NO_MESSAGE                \
        )

/**
 * @brief Macro. Reports internal XMLSec errors.
 * @details Macro. The XMLSec library macro for reporting internal XMLSec errors.
 * @param errorFunction the failed function name.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param the extra message param.
 */
#define xmlSecInternalError2(errorFunction, errorObject, msg, param) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,          \
                    (msg), (param)                          \
        )

/**
 * @brief Macro. Reports internal XMLSec errors.
 * @details Macro. The XMLSec library macro for reporting internal XMLSec errors.
 * @param errorFunction the failed function name.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param1 the extra message param1.
 * @param param2 the extra message param2.
 */
#define xmlSecInternalError3(errorFunction, errorObject, msg, param1, param2) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,          \
                    (msg), (param1), (param2)               \
        )

/**
 * @brief Macro. Reports internal XMLSec errors.
 * @details Macro. The XMLSec library macro for reporting internal XMLSec errors.
 * @param errorFunction the failed function name.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param1 the extra message param1.
 * @param param2 the extra message param2.
 * @param param3 the extra message param3.
 */
#define xmlSecInternalError4(errorFunction, errorObject, msg, param1, param2, param3) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,          \
                    (msg), (param1), (param2), (param3)     \
        )

/**
 * @brief Macro. Reports xmlMalloc() errors.
 * @details Macro. The XMLSec library macro for reporting xmlMalloc() errors.
 * @param allocSize the failed allocation size.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecMallocError(allocSize, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    "xmlMalloc",                            \
                    XMLSEC_ERRORS_R_MALLOC_FAILED,          \
                    "size=" XMLSEC_SIZE_T_FMT, (size_t)(allocSize) \
        )

/**
 * @brief Macro. Reports xmlStrdup() errors.
 * @details Macro. The XMLSec library macro for reporting xmlStrdup() errors.
 * @param str the failed string.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecStrdupError(str, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    "xmlStrdup",                            \
                    XMLSEC_ERRORS_R_STRDUP_FAILED,          \
                    "size=%d", xmlStrlen(str)               \
        )

/**
 * @brief Macro. Reports generic XML errors.
 * @details Macro. The XMLSec library macro for reporting generic XML errors.
 * @param errorFunction the failed function.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecXmlError(errorFunction, errorObject) \
    {                                                 \
        const xmlError * error = xmlGetLastError();        \
        int code = (error != NULL) ? error->code : 0; \
        const char* message = (error != NULL) ? error->message : NULL; \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   (errorFunction),                   \
                   XMLSEC_ERRORS_R_XML_FAILED,        \
                   "xml error: %d: %s",               \
                   code, xmlSecErrorsSafeString(message) \
        );                                            \
    }

/**
 * @brief Macro. Reports generic XML errors.
 * @details Macro. The XMLSec library macro for reporting generic XML errors.
 * @param errorFunction the failed function.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param the extra message param.
 */
#define xmlSecXmlError2(errorFunction, errorObject, msg, param) \
    {                                                 \
        const xmlError * error = xmlGetLastError();        \
        int code = (error != NULL) ? error->code : 0; \
        const char* message = (error != NULL) ? error->message : NULL; \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   (errorFunction),                   \
                   XMLSEC_ERRORS_R_XML_FAILED,        \
                   msg "; xml error: %d: %s",        \
                   (param), code, xmlSecErrorsSafeString(message) \
        );                                            \
    }

/**
 * @brief Macro. Reports XML parser errors.
 * @details Macro. The XMLSec library macro for reporting XML parser errors.
 * @param errorFunction the failed function.
 * @param ctxt the parser context.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecXmlParserError(errorFunction, ctxt, errorObject) \
    {                                                 \
        const xmlError * error = xmlCtxtGetLastError(ctxt);\
        int code = (error != NULL) ? error->code : 0; \
        const char* message = (error != NULL) ? error->message : NULL; \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   (errorFunction),                   \
                   XMLSEC_ERRORS_R_XML_FAILED,        \
                   "xml error: %d: %s",               \
                   code, xmlSecErrorsSafeString(message) \
        );                                            \
    }

/**
 * @brief Macro. Reports XML parser errors.
 * @details Macro. The XMLSec library macro for reporting XML parser errors.
 * @param errorFunction the failed function.
 * @param ctxt the parser context.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param the extra message param.
 */
#define xmlSecXmlParserError2(errorFunction, ctxt, errorObject, msg, param) \
    {                                                 \
        const xmlError * error = xmlCtxtGetLastError(ctxt);\
        int code = (error != NULL) ? error->code : 0; \
        const char* message = (error != NULL) ? error->message : NULL; \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   (errorFunction),                   \
                   XMLSEC_ERRORS_R_XML_FAILED,        \
                   msg "; xml error: %d: %s",         \
                   (param), code, xmlSecErrorsSafeString(message) \
        );                                            \
    }

/**
 * @brief Macro. Reports XSLT errors.
 * @details Macro. The XMLSec library macro for reporting XSLT errors.
 * @param errorFunction the failed function.
 * @param ctxt the parser context.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecXsltError(errorFunction, ctxt, errorObject) \
    {                                                 \
        const xmlError * error = xmlGetLastError();        \
        int code = (error != NULL) ? error->code : 0; \
        const char* message = (error != NULL) ? error->message : NULL; \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   (errorFunction),                   \
                   XMLSEC_ERRORS_R_XSLT_FAILED,       \
                   "xslt error: %d: %s",              \
                   code, xmlSecErrorsSafeString(message) \
        );                                            \
    }

/**
 * @brief Macro. Reports IO errors.
 * @details Macro. The XMLSec library macro for reporting IO errors.
 * @param errorFunction the failed function.
 * @param name the filename, function name, uri, etc.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
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
 * @brief Macro. Reports "not implemented" errors.
 * @details Macro. The XMLSec library macro for reporting "not implemented" errors.
 * @param msg the extra message.
 */
#define xmlSecNotImplementedError(msg) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    NULL,                                   \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,        \
                    "details=%s",                           \
                    xmlSecErrorsSafeString(msg)         \
        )

/**
 * @brief Macro. Reports "not implemented" errors.
 * @details Macro. The XMLSec library macro for reporting "not implemented" errors.
 * @param msg the extra message.
 * @param param the extra message param.
 */
#define xmlSecNotImplementedError2(msg, param) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    NULL,                                   \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,        \
                    (msg), (param)                          \
        )

/**
 * @brief Macro. Reports "invalid size" errors expecting exact match.
 * @details Macro. The XMLSec library macro for reporting "invalid size" errors when we expect exact match.
 * @param name the name of the variable, parameter, etc.
 * @param actual the actual value.
 * @param expected the expected value.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidSizeError(name, actual, expected, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_SIZE,           \
                    "invalid size for '%s': actual=" XMLSEC_SIZE_FMT " is not equal to expected=" XMLSEC_SIZE_FMT, \
                    xmlSecErrorsSafeString(name),           \
                    (actual),                               \
                    (expected)                              \
        )

/**
 * @brief Macro. Reports "invalid size" errors expecting minimum size.
 * @details Macro. The XMLSec library macro for reporting "invalid size" errors when we expect at least the expected size.
 * @param name the name of the variable, parameter, etc.
 * @param actual the actual value.
 * @param expected the expected value.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidSizeLessThanError(name, actual, expected, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_SIZE,           \
                    "invalid size for '%s': actual=" XMLSEC_SIZE_FMT " is less than expected=" XMLSEC_SIZE_FMT, \
                    xmlSecErrorsSafeString(name),           \
                    (actual),                               \
                    (expected)                              \
        )

/**
 * @brief Macro. Reports "invalid size" errors expecting maximum size.
 * @details Macro. The XMLSec library macro for reporting "invalid size" errors when we expect at most the expected size.
 * @param name the name of the variable, parameter, etc.
 * @param actual the actual value.
 * @param expected the expected value.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidSizeMoreThanError(name, actual, expected, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,        \
                    "invalid size for '%s': actual=" XMLSEC_SIZE_FMT " is more than expected=" XMLSEC_SIZE_FMT, \
                    xmlSecErrorsSafeString(name),           \
                    (actual),                               \
                    (expected)                              \
        )

/**
 * @brief Macro. Reports "invalid size" errors expecting a multiple of divider.
 * @details Macro. The XMLSec library macro for reporting "invalid size" errors when we expect the size to be a multiple of the divider.
 * @param name the name of the variable, parameter, etc.
 * @param actual the actual value.
 * @param divider the expected divider.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidSizeNotMultipleOfError(name, actual, divider, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,        \
                    "invalid size for '%s': actual=" XMLSEC_SIZE_FMT " is not a multiple of " XMLSEC_SIZE_FMT, \
                    xmlSecErrorsSafeString(name),           \
                    (actual),                               \
                    (divider)                               \
        )

/**
 * @brief Macro. Reports "invalid size" errors (other).
 * @details Macro. The XMLSec library macro for reporting "invalid size" errors when we expect exact match.
 * @param msg the message about the error.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidSizeOtherError(msg, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_SIZE,           \
                    "invalid size: %s",                     \
                    xmlSecErrorsSafeString(msg)             \
        )

/**
 * @brief Macro. Reports "invalid data" errors.
 * @details Macro. The XMLSec library macro for reporting "invalid data" errors.
 * @param msg the msg with explanation.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidDataError(msg, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_DATA,           \
                    "%s",                                   \
                    xmlSecErrorsSafeString(msg)             \
        )


/**
 * @brief Macro. Reports "invalid data" errors for string values.
 * @details Macro. The XMLSec library macro for reporting "invalid data" errors for string.
 * @param name the name of the variable, parameter, etc.
 * @param actual the actual string value.
 * @param expected the expected value(s) as a string.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidStringDataError(name, actual, expected, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_DATA,           \
                    "invalid data for '%s': actual='%s' and expected %s", \
                    xmlSecErrorsSafeString(name),           \
                    xmlSecErrorsSafeString(actual),         \
                    (expected)                              \
        )

/**
 * @brief Macro. Reports "invalid data" errors for integer values.
 * @details Macro. The XMLSec library macro for reporting "invalid data" errors for integers.
 * @param name the name of the variable, parameter, etc.
 * @param actual the actual integer value.
 * @param expected the expected value(s) as a string.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidIntegerDataError(name, actual, expected, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_DATA,           \
                    "invalid data for '%s': actual=%d and expected %s", \
                    xmlSecErrorsSafeString(name),           \
                    (actual),                               \
                    (expected)                              \
        )

/**
 * @brief Macro. Reports "invalid data" errors for integer values.
 * @details Macro. The XMLSec library macro for reporting "invalid data" errors for integers.
 * @param name1 the name of the first variable, parameter, etc.
 * @param actual1 the actual first integer value.
 * @param name2 the name of the second variable, parameter, etc.
 * @param actual2 the actual second integer value.
 * @param expected the expected value(s) as a string.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidIntegerDataError2(name1, actual1, name2, actual2, expected, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_DATA,           \
                    "invalid data: actual value '%s'=%d, actual value '%s'=%d and expected %s", \
                    xmlSecErrorsSafeString(name1),          \
                    (actual1),                              \
                    xmlSecErrorsSafeString(name2),          \
                    (actual2),                              \
                    (expected)                              \
        )

/**
 * @brief Macro. Reports "invalid data" errors for xmlSecSize values.
 * @details Macro. The XMLSec library macro for reporting "invalid data" errors for xmlSecSize.
 * @param name the name of the variable, parameter, etc.
 * @param actual the actual xmlSecSize value.
 * @param expected the expected value(s) as a string.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidSizeDataError(name, actual, expected, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_DATA,           \
                    "invalid data for '%s': actual=" XMLSEC_SIZE_FMT " and expected %s", \
                    xmlSecErrorsSafeString(name),           \
                    (actual),                               \
                    (expected)                              \
        )

/**
 * @brief Macro. Reports "invalid data" errors for xmlSecSize values.
 * @details Macro. The XMLSec library macro for reporting "invalid data" errors for xmlSecSize.
 * @param name1 the name of the first variable, parameter, etc.
 * @param actual1 the actual first xmlSecSize value.
 * @param name2 the name of the second variable, parameter, etc.
 * @param actual2 the actual second xmlSecSize value.
 * @param expected the expected value(s) as a string.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidSizeDataError2(name1, actual1, name2, actual2, expected, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_DATA,           \
                    "invalid data: actual value '%s'=" XMLSEC_SIZE_FMT ", actual value '%s'=" XMLSEC_SIZE_FMT " and expected %s", \
                    xmlSecErrorsSafeString(name1),          \
                    (actual1),                              \
                    xmlSecErrorsSafeString(name2),          \
                    (actual2),                              \
                    (expected)                              \
        )

/**
 * @brief Macro. Reports "invalid type" errors.
 * @details Macro. The XMLSec library macro for reporting "invalid type" errors.
 * @param msg the msg with explanation.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidTypeError(msg, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_TYPE,           \
                    "%s",                                   \
                    xmlSecErrorsSafeString(msg)             \
        )

/**
 * @brief Macro. Reports "invalid type" errors for string values.
 * @details Macro. The XMLSec library macro for reporting "invalid type" errors for string.
 * @param name the name of the variable, parameter, etc.
 * @param actual the actual value as a string.
 * @param expected the expected value(s) as a string.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidStringTypeError(name, actual, expected, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_TYPE,           \
                    "invalid type for '%s': actual='%s' and expected %s", \
                    xmlSecErrorsSafeString(name),           \
                    xmlSecErrorsSafeString(actual),         \
                    (expected)                              \
        )

/**
 * @brief Macro. Reports "invalid type" errors for integer values.
 * @details Macro. The XMLSec library macro for reporting "invalid type" errors for integers.
 * @param name the name of the variable, parameter, etc.
 * @param actual the actual integer value.
 * @param expected the expected value(s) as a string.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidIntegerTypeError(name, actual, expected, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_TYPE,           \
                    "invalid type for '%s': actual=%d and expected %s", \
                    xmlSecErrorsSafeString(name),           \
                    (actual),                               \
                    (expected)                              \
        )

/**
 * @brief Macro. Reports "invalid type" errors for integer values.
 * @details Macro. The XMLSec library macro for reporting "invalid type" errors for integers.
 * @param name1 the name of the first variable, parameter, etc.
 * @param actual1 the actual first integer value.
 * @param name2 the name of the second variable, parameter, etc.
 * @param actual2 the actual second integer value.
 * @param expected the expected value(s) as a string.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidIntegerTypeError2(name1, actual1, name2, actual2, expected, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_TYPE,           \
                    "invalid type: actual value '%s'=%d, actual value '%s'=%d and expected %s", \
                    xmlSecErrorsSafeString(name1),          \
                    (actual1),                              \
                    xmlSecErrorsSafeString(name2),          \
                    (actual2),                              \
                    (expected)                              \
        )


/**
 * @brief Macro. Reports "unsupported enum type" errors.
 * @details Macro. The XMLSec library macro for reporting "unsupported enum type" errors.
 * @param name the name of the variable, parameter, etc.
 * @param actual the actual value.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecUnsupportedEnumValueError(name, actual, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_TYPE,           \
                    "unsupported value for '%s': " XMLSEC_ENUM_FMT, \
                    xmlSecErrorsSafeString(name),           \
                    XMLSEC_ENUM_CAST(actual)                \
        )


/**
 * @brief Macro. Reports invalid node errors.
 * @details Macro. The XMLSec library macro for reporting an invalid node errors.
 * @param actualNode the actual node.
 * @param expectedNodeName the expected node name.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
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
 * @brief Macro. Reports invalid node content errors.
 * @details Macro. The XMLSec library macro for reporting an invalid node content errors.
 * @param node the node.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param reason the reason why node content is invalid.
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
 * @brief Macro. Reports invalid node content errors.
 * @details Macro. The XMLSec library macro for reporting an invalid node content errors.
 * @param node the node.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param the extra message param.
 */
#define xmlSecInvalidNodeContentError2(node, errorObject, msg, param) \
    {                                                 \
        const char* nName = xmlSecNodeGetName(node);  \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   NULL,                              \
                   XMLSEC_ERRORS_R_INVALID_NODE_CONTENT, \
                   msg "; node=%s",                   \
                   (param),                           \
                   xmlSecErrorsSafeString(nName)      \
        );                                            \
    }

/**
 * @brief Macro. Reports invalid node content errors.
 * @details Macro. The XMLSec library macro for reporting an invalid node content errors.
 * @param node the node.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param1 the extra message param1.
 * @param param2 the extra message param2.
 */
#define xmlSecInvalidNodeContentError3(node, errorObject, msg, param1, param2) \
    {                                                 \
        const char* nName = xmlSecNodeGetName(node);  \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)(errorObject),        \
                   NULL,                              \
                   XMLSEC_ERRORS_R_INVALID_NODE_CONTENT, \
                   msg "; node=%s",                   \
                   (param1),                          \
                   (param2),                          \
                   xmlSecErrorsSafeString(nName)      \
        );                                            \
    }


/**
 * @brief Macro. Reports invalid node attribute errors.
 * @details Macro. The XMLSec library macro for reporting an invalid node attribute errors.
 * @param node the node.
 * @param attrName the attribute name.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param reason the reason why node content is invalid.
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
 * @brief Macro. Reports node already present errors.
 * @details Macro. The XMLSec library macro for reporting node already present errors.
 * @param parent the parent node.
 * @param nodeName the node name.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
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
 * @brief Macro. Reports unexpected node errors.
 * @details Macro. The XMLSec library macro for reporting an invalid node errors.
 * @param node the node.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
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
 * @brief Macro. Reports node not found errors.
 * @details Macro. The XMLSec library macro for reporting node not found errors.
 * @param errorFunction the failed function.
 * @param startNode the search start node.
 * @param targetNodeName the expected child node name.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
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
 * @brief Macro. Reports invalid transform errors.
 * @details Macro. The XMLSec library macro for reporting an invalid transform errors.
 * @param transform the transform.
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
 * @brief Macro. Reports invalid transform errors.
 * @details Macro. The XMLSec library macro for reporting an invalid transform errors.
 * @param transform the transform.
 * @param msg the extra message.
 * @param param the extra message param.
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
 * @brief Macro. Reports invalid transform errors.
 * @details Macro. The XMLSec library macro for reporting an invalid transform errors.
 * @param transform the transform.
 * @param msg the extra message.
 * @param param1 the extra message param.
 * @param param2 the extra message param.
 */
#define xmlSecInvalidTransfromError3(transform, msg, param1, param2) \
    {                                                 \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)xmlSecTransformGetName(transform), \
                   NULL,                              \
                   XMLSEC_ERRORS_R_INVALID_TRANSFORM, \
                   (msg), (param1), (param2)          \
        );                                            \
    }

/**
 * @brief Macro. Reports invalid transform status errors.
 * @details Macro. The XMLSec library macro for reporting an invalid transform status errors.
 * @param transform the transform.
 */
#define xmlSecInvalidTransfromStatusError(transform)   \
    {                                                  \
        xmlSecError(XMLSEC_ERRORS_HERE,                \
                   (const char*)xmlSecTransformGetName(transform), \
                   NULL,                               \
                   XMLSEC_ERRORS_R_INVALID_STATUS,     \
                   "transformStatus=" XMLSEC_ENUM_FMT, \
                   XMLSEC_ENUM_CAST((transform)->status) \
        );                                             \
    }

/**
 * @brief Macro. Reports invalid transform status errors.
 * @details Macro. The XMLSec library macro for reporting an invalid transform status errors.
 * @param transform the transform.
 * @param msg the extra message.
 */
#define xmlSecInvalidTransfromStatusError2(transform, msg) \
    {                                                 \
        xmlSecError(XMLSEC_ERRORS_HERE,               \
                   (const char*)xmlSecTransformGetName(transform), \
                   NULL,                              \
                   XMLSEC_ERRORS_R_INVALID_STATUS,    \
                   "transformStatus=" XMLSEC_ENUM_FMT "; msg=%s", \
                   XMLSEC_ENUM_CAST((transform)->status),         \
                   (msg)                              \
        );                                            \
    }

/**
 * @brief Macro. Reports invalid key data size errors.
 * @details Macro. The XMLSec library macro for reporting "invalid keydata size" errors.
 * @param name the name of the variable, parameter, etc.
 * @param actual the actual value.
 * @param expected the expected value(s).
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidKeyDataSizeError(actual, expected, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_KEY_DATA_SIZE,  \
                    "invalid key data size: actual=" XMLSEC_SIZE_FMT " and expected=" XMLSEC_SIZE_FMT, \
                    (actual),                               \
                    (expected)                              \
        )

/**
 * @brief Macro. Reports invalid (zero) key data size errors.
 * @details Macro. The XMLSec library macro for reporting "invalid keydata size" errors.
 * @param name the name of the variable, parameter, etc.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecInvalidZeroKeyDataSizeError(errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERRORS_R_INVALID_KEY_DATA_SIZE,  \
                    "invalid zero key data size"            \
        )

/**
 * @brief Macro. Reports impossible cast errors.
 * @details Macro. The XMLSec library macro for reporting impossible cast errors.
 * @param srcType the source value type.
 * @param srcVal the source value.
 * @param srcFmt the source type printf format (e.g. "%d").
 * @param dstType the destination cast type.
 * @param dstMinVal the destination type min value.
 * @param dstMaxVal the destination type max value.
 * @param dstFmt the destination type printf format (e.g. "%lu").
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecImpossibleCastError(srcType, srcVal, srcFmt, dstType, dstMinVal, dstMaxVal, dstFmt, errorObject) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    XMLSEC_ERROR_R_CAST_IMPOSSIBLE,         \
                    "src-type=" #srcType "; src-val=" srcFmt  \
                    ";dst-type=" #dstType "; dst-min=" dstFmt \
                    ";dst-max=" dstFmt "",                  \
                    (srcVal), (dstMinVal), (dstMaxVal)      \
        )

/**
 * @brief Macro. Reports other XMLSec errors.
 * @details Macro. The XMLSec library macro for reporting other XMLSec errors.
 * @param code the error code.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param details the error message.
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
 * @brief Macro. Reports other XMLSec errors.
 * @details Macro. The XMLSec library macro for reporting other XMLSec errors.
 * @param code the error code.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param the extra message param.
 */
#define xmlSecOtherError2(code, errorObject, msg, param)    \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    (code),                                 \
                    (msg), (param)                          \
        )

/**
 * @brief Macro. Reports other XMLSec errors.
 * @details Macro. The XMLSec library macro for reporting other XMLSec errors.
 * @param code the error code.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param1 the extra message param.
 * @param param2 the extra message param.
 */
#define xmlSecOtherError3(code, errorObject, msg, param1, param2) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    (code),                                 \
                    (msg), (param1), (param2)               \
        )

/**
 * @brief Macro. Reports other XMLSec errors.
 * @details Macro. The XMLSec library macro for reporting other XMLSec errors.
 * @param code the error code.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param1 the extra message param.
 * @param param2 the extra message param.
 * @param param3 the extra message param.
 */
#define xmlSecOtherError4(code, errorObject, msg, param1, param2, param3) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    (code),                                 \
                    (msg), (param1), (param2), (param3)     \
        )

/**
 * @brief Macro. Reports other XMLSec errors.
 * @details Macro. The XMLSec library macro for reporting other XMLSec errors.
 * @param code the error code.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param1 the extra message param.
 * @param param2 the extra message param.
 * @param param3 the extra message param.
 * @param param4 the extra message param.
 */
#define xmlSecOtherError5(code, errorObject, msg, param1, param2, param3, param4) \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    NULL,                                   \
                    (code),                                 \
                    (msg), (param1), (param2), (param3), (param4) \
        )


XMLSEC_EXPORT int   xmlSecErrorsPrintCryptoLibraryLogOnExitIsEnabled    (void);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_ERROR_HELPERS_H__ */
