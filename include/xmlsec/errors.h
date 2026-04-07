/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_ERRORS_H__
#define __XMLSEC_ERRORS_H__

/**
 * @defgroup xmlsec_core_errors Error Reporting
 * @ingroup xmlsec_core
 * @brief Error codes and error-reporting functions.
 * @{
 */

#include <xmlsec/exports.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/******************************************************************************
 *
 * Error codes
 *
  *****************************************************************************/
/**
 * @brief An XMLSec function failed.
 */
#define XMLSEC_ERRORS_R_XMLSEC_FAILED                   1

/**
 * @brief Failed to allocate memory error.
 */
#define XMLSEC_ERRORS_R_MALLOC_FAILED                   2

/**
 * @brief Failed to duplicate string error.
 */
#define XMLSEC_ERRORS_R_STRDUP_FAILED                   3

/**
 * @brief Crypto (e.g. OpenSSL) function failed.
 */
#define XMLSEC_ERRORS_R_CRYPTO_FAILED                   4

/**
 * @brief LibXML function failed.
 */
#define XMLSEC_ERRORS_R_XML_FAILED                      5

/**
 * @brief LibXSLT function failed.
 */
#define XMLSEC_ERRORS_R_XSLT_FAILED                     6

/**
 * @brief IO operation failed.
 */
#define XMLSEC_ERRORS_R_IO_FAILED                       7

/**
 * @brief The feature is disabled during compilation.
 * @details The feature is disabled during compilation. Check './configure --help' for details on how to enable it.
 */
#define XMLSEC_ERRORS_R_DISABLED                        8

/**
 * @brief Feature is not implemented.
 */
#define XMLSEC_ERRORS_R_NOT_IMPLEMENTED                 9

/**
 * @brief The configuration is invalid.
 */
#define XMLSEC_ERRORS_R_INVALID_CONFIG                  10

/**
 * @brief Invalid size.
 */
#define XMLSEC_ERRORS_R_INVALID_SIZE                    11

/**
 * @brief Invalid data.
 */
#define XMLSEC_ERRORS_R_INVALID_DATA                    12

/**
 * @brief Invalid result.
 */
#define XMLSEC_ERRORS_R_INVALID_RESULT                  13

/**
 * @brief Invalid type.
 */
#define XMLSEC_ERRORS_R_INVALID_TYPE                    14

/**
 * @brief Invalid operation.
 */
#define XMLSEC_ERRORS_R_INVALID_OPERATION               15

/**
 * @brief Invalid status.
 */
#define XMLSEC_ERRORS_R_INVALID_STATUS                  16

/**
 * @brief Invalid format.
 */
#define XMLSEC_ERRORS_R_INVALID_FORMAT                  17

/**
 * @brief The data do not match our expectation.
 */
#define XMLSEC_ERRORS_R_DATA_NOT_MATCH                  18

/**
 * @brief Version mismatch.
 */
#define XMLSEC_ERRORS_R_INVALID_VERSION                 19

/**
 * @brief Invalid node.
 */
#define XMLSEC_ERRORS_R_INVALID_NODE                    21

/**
 * @brief Invalid node content.
 */
#define XMLSEC_ERRORS_R_INVALID_NODE_CONTENT            22

/**
 * @brief Invalid node attribute.
 */
#define XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE          23

/**
 * @brief Missing node attribute.
 */
#define XMLSEC_ERRORS_R_MISSING_NODE_ATTRIBUTE          25

/**
 * @brief Node already present.
 */
#define XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT            26

/**
 * @brief Unexpected node.
 */
#define XMLSEC_ERRORS_R_UNEXPECTED_NODE                 27

/**
 * @brief Node not found.
 */
#define XMLSEC_ERRORS_R_NODE_NOT_FOUND                  28

/**
 * @brief This transform is invalid.
 */
#define XMLSEC_ERRORS_R_INVALID_TRANSFORM               31

/**
 * @brief Key is invalid for this transform.
 */
#define XMLSEC_ERRORS_R_INVALID_TRANSFORM_KEY           32

/**
 * @brief Invalid URI type.
 */
#define XMLSEC_ERRORS_R_INVALID_URI_TYPE                33

/**
 * @brief The transform requires the same document as context.
 * @details The transform requires the input document to be the same as context.
 */
#define XMLSEC_ERRORS_R_TRANSFORM_SAME_DOCUMENT_REQUIRED        34

/**
 * @brief The transform is disabled.
 */
#define XMLSEC_ERRORS_R_TRANSFORM_DISABLED              35

/**
 * @brief Invalid or unsupported algorithm.
 */
#define XMLSEC_ERRORS_R_INVALID_ALGORITHM               36

/**
 * @brief Key data is invalid.
 */
#define XMLSEC_ERRORS_R_INVALID_KEY_DATA                41

/**
 * @brief Key data is not found.
 */
#define XMLSEC_ERRORS_R_KEY_DATA_NOT_FOUND              42

/**
 * @brief The key data already exists.
 */
#define XMLSEC_ERRORS_R_KEY_DATA_ALREADY_EXIST          43

/**
 * @brief Invalid key size.
 */
#define XMLSEC_ERRORS_R_INVALID_KEY_DATA_SIZE           44

/**
 * @brief Key not found.
 */
#define XMLSEC_ERRORS_R_KEY_NOT_FOUND                   45

/**
 * @brief The key data type is disabled.
 */
#define XMLSEC_ERRORS_R_KEYDATA_DISABLED                46

/**
 * @brief Max allowed retrievals level reached.
 */
#define XMLSEC_ERRORS_R_MAX_RETRIEVALS_LEVEL            51

/**
 * @brief Key data type mismatch in dsig:RetrievalMethod node.
 * @details The retrieved key data type does not match the one specified in the &lt;dsig:RetrievalMethod/&gt; node.
 */
#define XMLSEC_ERRORS_R_MAX_RETRIEVAL_TYPE_MISMATCH     52

/**
 * @brief Max allowed KeyInfoReference level reached.
 */
#define XMLSEC_ERRORS_R_MAX_KEYINFOREFERENCE_LEVEL        51

/**
 * @brief Max EncryptedKey level reached.
 */
#define XMLSEC_ERRORS_R_MAX_ENCKEY_LEVEL                61

/**
 * @brief Certificate verification failed.
 */
#define XMLSEC_ERRORS_R_CERT_VERIFY_FAILED              71

/**
 * @brief Requested certificate is not found.
 */
#define XMLSEC_ERRORS_R_CERT_NOT_FOUND                  72

/**
 * @brief The certificate is revoked.
 */
#define XMLSEC_ERRORS_R_CERT_REVOKED                    73

/**
 * @brief Failed to get certificate issuer.
 */
#define XMLSEC_ERRORS_R_CERT_ISSUER_FAILED              74

/**
 * @brief "Not valid before" verification failed.
 */
#define XMLSEC_ERRORS_R_CERT_NOT_YET_VALID              75

/**
 * @brief "Not valid after" verification failed.
 */
#define XMLSEC_ERRORS_R_CERT_HAS_EXPIRED                76

/**
 * @brief CRL verification failed.
 */
#define XMLSEC_ERRORS_R_CRL_VERIFY_FAILED              77

/**
 * @brief "Last update" CRL verification failed.
 */
#define XMLSEC_ERRORS_R_CRL_NOT_YET_VALID              78

/**
 * @brief "Next update" verification failed.
 */
#define XMLSEC_ERRORS_R_CRL_HAS_EXPIRED                79

/**
 * @brief The &lt;dsig:Reference/&gt; nodes not found.
 */
#define XMLSEC_ERRORS_R_DSIG_NO_REFERENCES              81

/**
 * @brief The &lt;dsig:Reference/&gt; validation failed.
 */
#define XMLSEC_ERRORS_R_DSIG_INVALID_REFERENCE          82

/**
 * @brief Invalid assertion.
 */
#define XMLSEC_ERRORS_R_ASSERTION                       100

/**
 * @brief Impossible to cast from one type to another.
 */
#define XMLSEC_ERROR_R_CAST_IMPOSSIBLE                  101

/**
 * @brief The maximum xmlsec errors number.
 */
#define XMLSEC_ERRORS_MAX_NUMBER                        256



/******************************************************************************
 *
 * Error functions
 *
  *****************************************************************************/
/**
 * @brief The errors reporting callback function.
 * @param line the error location line number (__LINE__ macro).
 * @param func the error location function name (__func__ macro).
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param errorSubject the error specific error subject.
 * @param reason the error code.
 * @param msg the additional error message.
 */
typedef void (*xmlSecErrorsCallback)                            (const char* file,
                                                                 int line,
                                                                 const char* func,
                                                                 const char* errorObject,
                                                                 const char* errorSubject,
                                                                 int reason,
                                                                 const char* msg);


XMLSEC_EXPORT void              xmlSecErrorsInit                (void);
XMLSEC_EXPORT void              xmlSecErrorsShutdown            (void);
XMLSEC_EXPORT void              xmlSecErrorsSetCallback         (xmlSecErrorsCallback callback);
XMLSEC_EXPORT void              xmlSecErrorsDefaultCallback     (const char* file,
                                                                 int line,
                                                                 const char* func,
                                                                 const char* errorObject,
                                                                 const char* errorSubject,
                                                                 int reason,
                                                                 const char* msg);
XMLSEC_EXPORT void              xmlSecErrorsDefaultCallbackEnableOutput
                                                                (int enabled);

XMLSEC_EXPORT int               xmlSecErrorsGetCode             (xmlSecSize pos);
XMLSEC_EXPORT const char*       xmlSecErrorsGetMsg              (xmlSecSize pos);


XMLSEC_EXPORT void              xmlSecErrorsPrintCryptoLibraryLogOnExitSet      (int enabled);

#if !defined(__XMLSEC_FUNCTION__)

/* __FUNCTION__ is defined for MSC compiler < MS VS .NET 2003 */
#if defined(_MSC_VER) && (_MSC_VER >= 1300)
#define __XMLSEC_FUNCTION__ __FUNCTION__

/* and for GCC too */
#elif defined(__GNUC__)
/**
 * @brief The current function name (compiler-specific).
 */
#define __XMLSEC_FUNCTION__ __func__

/* fallback for __FUNCTION__ */
#else
#define __XMLSEC_FUNCTION__  ""
#endif

#endif /*!defined(__XMLSEC_FUNCTION__) */

/**
 * @brief The macro specifying the error location (file, line, function) for xmlSecError().
 * @details The macro that specifies the location (file, line and function) for the xmlSecError() function.
 */
#define XMLSEC_ERRORS_HERE                      __FILE__,__LINE__,__XMLSEC_FUNCTION__
#ifdef __GNUC__
/**
 * @brief Printf-style format-string attribute for xmlSecError() (GCC/Clang only).
 * @details Printf-style format-string attribute for the xmlSecError() function (GCC/Clang only; empty on other compilers).
 */
#define XMLSEC_ERRORS_PRINTF_ATTRIBUTE          __attribute__ ((format (printf, 7, 8)))
#else /* __GNUC__ */
#define XMLSEC_ERRORS_PRINTF_ATTRIBUTE
#endif /* __GNUC__ */

/**
 * @brief Macro. Returns @p str if it is not NULL or pointer to "NULL" otherwise.
 * @param str the string.
 */
#define xmlSecErrorsSafeString(str) \
        (((str) != NULL) ? ((const char*)(str)) : (const char*)"NULL")

/**
 * @brief Empty error message " ".
 */
#define XMLSEC_ERRORS_NO_MESSAGE                " "


XMLSEC_EXPORT void xmlSecError                          (const char* file,
                                                         int line,
                                                         const char* func,
                                                         const char* errorObject,
                                                         const char* errorSubject,
                                                         int reason,
                                                         const char* msg, ...) XMLSEC_ERRORS_PRINTF_ATTRIBUTE;

/******************************************************************************
 *
 * Assertions
 *
  *****************************************************************************/
/**
 * @brief Macro. Verifies that @p is true and calls return() otherwise.
 * @param p the expression.
 */
#define xmlSecAssert( p ) \
        if(!( p ) ) { \
            xmlSecError(XMLSEC_ERRORS_HERE, \
                        NULL, \
                        #p, \
                        XMLSEC_ERRORS_R_ASSERTION, \
                        XMLSEC_ERRORS_NO_MESSAGE); \
            return; \
        }

/**
 * @brief Macro. Verifies that @p is true and calls return(@p ret) otherwise.
 * @param p the expression.
 * @param ret the return value.
 */
#define xmlSecAssert2( p, ret ) \
        if(!( p ) ) { \
            xmlSecError(XMLSEC_ERRORS_HERE, \
                        NULL, \
                        #p, \
                        XMLSEC_ERRORS_R_ASSERTION, \
                        XMLSEC_ERRORS_NO_MESSAGE); \
            return(ret); \
        }


#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_core_errors */

#endif /* __XMLSEC_ERRORS_H__ */
