/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_core_errors
 * @brief Error reporting and logging functions.
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/private.h>
#include <xmlsec/errors.h>

/* Must be bigger than fatal_error */
#define XMLSEC_ERRORS_BUFFER_SIZE       1024

/* Must fit into xmlChar[XMLSEC_ERRORS_BUFFER_SIZE] */
static const xmlChar fatal_error[] = "Can not format error message";

typedef struct _xmlSecErrorDescription                  xmlSecErrorDescription, *xmlSecErrorDescriptionPtr;
struct _xmlSecErrorDescription {
    int                 errorCode;
    const char*         errorMsg;
};

static const xmlSecErrorDescription xmlSecErrorsTable[XMLSEC_ERRORS_MAX_NUMBER + 1] = {
  { XMLSEC_ERRORS_R_XMLSEC_FAILED,              "xmlsec library function failed" },
  { XMLSEC_ERRORS_R_MALLOC_FAILED,              "malloc function failed" },
  { XMLSEC_ERRORS_R_STRDUP_FAILED,              "strdup function failed" },
  { XMLSEC_ERRORS_R_CRYPTO_FAILED,              "crypto library function failed" },
  { XMLSEC_ERRORS_R_XML_FAILED,                 "libxml2 library function failed" },
  { XMLSEC_ERRORS_R_XSLT_FAILED,                "libxslt library function failed" },
  { XMLSEC_ERRORS_R_IO_FAILED,                  "io function failed" },
  { XMLSEC_ERRORS_R_DISABLED,                   "feature is disabled" },
  { XMLSEC_ERRORS_R_NOT_IMPLEMENTED,            "feature is not implemented" },
  { XMLSEC_ERRORS_R_INVALID_CONFIG,             "invalid configuration" },
  { XMLSEC_ERRORS_R_INVALID_SIZE,               "invalid size" },
  { XMLSEC_ERRORS_R_INVALID_DATA,               "invalid data" },
  { XMLSEC_ERRORS_R_INVALID_RESULT,             "invalid result" },
  { XMLSEC_ERRORS_R_INVALID_TYPE,               "invalid type" },
  { XMLSEC_ERRORS_R_INVALID_OPERATION,          "invalid operation" },
  { XMLSEC_ERRORS_R_INVALID_STATUS,             "invalid status" },
  { XMLSEC_ERRORS_R_INVALID_FORMAT,             "invalid format" },
  { XMLSEC_ERRORS_R_DATA_NOT_MATCH,             "data do not match" },
  { XMLSEC_ERRORS_R_INVALID_VERSION,            "invalid version" },
  { XMLSEC_ERRORS_R_INVALID_NODE,               "invalid node" },
  { XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,       "invalid node content" },
  { XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE,     "invalid node attribute" },
  { XMLSEC_ERRORS_R_MISSING_NODE_ATTRIBUTE,     "missing node attribute" },
  { XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,       "node already present" },
  { XMLSEC_ERRORS_R_UNEXPECTED_NODE,            "unexpected node" },
  { XMLSEC_ERRORS_R_NODE_NOT_FOUND,             "node node found" },
  { XMLSEC_ERRORS_R_INVALID_TRANSFORM,          "invalid transform" },
  { XMLSEC_ERRORS_R_INVALID_TRANSFORM_KEY,      "invalid transform key" },
  { XMLSEC_ERRORS_R_INVALID_URI_TYPE,           "invalid URI type" },
  { XMLSEC_ERRORS_R_TRANSFORM_SAME_DOCUMENT_REQUIRED,   "same document is required for transform" },
  { XMLSEC_ERRORS_R_TRANSFORM_DISABLED,         "transform is disabled" },
  { XMLSEC_ERRORS_R_INVALID_ALGORITHM,          "invalid or unsupported algorithm" },
  { XMLSEC_ERRORS_R_INVALID_KEY_DATA,           "invalid key data" },
  { XMLSEC_ERRORS_R_KEY_DATA_NOT_FOUND,         "key data is not found" },
  { XMLSEC_ERRORS_R_KEY_DATA_ALREADY_EXIST,     "key data already exist" },
  { XMLSEC_ERRORS_R_INVALID_KEY_DATA_SIZE,      "invalid key data size" },
  { XMLSEC_ERRORS_R_KEY_NOT_FOUND,              "key is not found" },
  { XMLSEC_ERRORS_R_KEYDATA_DISABLED,           "key data is disabled" },
  { XMLSEC_ERRORS_R_MAX_RETRIEVALS_LEVEL,       "maximum key retrieval level" },
  { XMLSEC_ERRORS_R_MAX_RETRIEVAL_TYPE_MISMATCH,"key retrieval type mismatch" },
  { XMLSEC_ERRORS_R_MAX_ENCKEY_LEVEL,           "maximum encrypted key level" },
  { XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,         "certificate verification failed" },
  { XMLSEC_ERRORS_R_CERT_NOT_FOUND,             "certificate is not found" },
  { XMLSEC_ERRORS_R_CERT_REVOKED,               "certificate is revoked" },
  { XMLSEC_ERRORS_R_CERT_ISSUER_FAILED,         "certificate issuer check failed" },
  { XMLSEC_ERRORS_R_CERT_NOT_YET_VALID,         "certificate is not yet valid" },
  { XMLSEC_ERRORS_R_CERT_HAS_EXPIRED,           "certificate has expired" },
  { XMLSEC_ERRORS_R_CRL_VERIFY_FAILED,          "CRL verification failed" },
  { XMLSEC_ERRORS_R_CRL_NOT_YET_VALID,          "CRL is not yet valid" },
  { XMLSEC_ERRORS_R_CRL_HAS_EXPIRED,            "CRL has expired" },
  { XMLSEC_ERRORS_R_DSIG_NO_REFERENCES,         "Reference nodes are not found" },
  { XMLSEC_ERRORS_R_DSIG_INVALID_REFERENCE,     "Reference verification failed" },
  { XMLSEC_ERRORS_R_ASSERTION,                  "assertion" },
  { 0,                                          NULL}
};

static xmlSecErrorsCallback xmlSecErrorsClbk = xmlSecErrorsDefaultCallback;
static int  xmlSecPrintErrorMessages = 1;       /* whether the error messages will be printed immediately */

static int gXmlSecErrorsPrintCryptoLibraryLogOnExitIsEnabled = 0;

/**
 * @brief Initializes the errors reporting.
 * @details Initializes the errors reporting. It is called from #xmlSecInit function.
 * and applications must not call this function directly.
 */
void
xmlSecErrorsInit(void) {
}

/**
 * @brief Cleanups the errors reporting.
 * @details Cleanups the errors reporting. It is called from #xmlSecShutdown function.
 * and applications must not call this function directly.
 */
void
xmlSecErrorsShutdown(void) {
}

/**
 * @brief Sets the errors callback function.
 * @details Sets the errors callback function to @p callback that will be called
 * every time an error occurs.
 * @param callback the new errors callback function.
 */
void
xmlSecErrorsSetCallback(xmlSecErrorsCallback callback) {
    xmlSecErrorsClbk = callback;
}

/**
 * @brief The default error reporting callback using LibXML.
 * @details The default error reporting callback that utilizes LibXML
 * error reporting xmlGenericError function.
 * @param file the error location file name (__FILE__ macro).
 * @param line the error location line number (__LINE__ macro).
 * @param func the error location function name (__FUNCTION__ macro).
 * @param errorObject the error specific error object
 * @param errorSubject the error specific error subject.
 * @param reason the error code.S
 * @param msg the additional error message.
 */
void
xmlSecErrorsDefaultCallback(const char* file, int line, const char* func,
                            const char* errorObject, const char* errorSubject,
                            int reason, const char* msg) {
    if(xmlSecPrintErrorMessages) {
        const char* error_msg = NULL;
        xmlSecSize i;

        for(i = 0; (i < XMLSEC_ERRORS_MAX_NUMBER) && (xmlSecErrorsGetMsg(i) != NULL); ++i) {
            if(xmlSecErrorsGetCode(i) == reason) {
                error_msg = xmlSecErrorsGetMsg(i);
                break;
            }
        }
        xmlGenericError(xmlGenericErrorContext,
            "func=%s:file=%s:line=%d:obj=%s:subj=%s:error=%d:%s:%s\n",
            (func != NULL) ? func : "unknown",
            (file != NULL) ? file : "unknown",
            line,
            (errorObject != NULL) ? errorObject : "unknown",
            (errorSubject != NULL) ? errorSubject : "unknown",
            reason,
            (error_msg != NULL) ? error_msg : "",
            (msg != NULL) ? msg : "");
    }
}

/**
 * @brief Enables or disables output from the default errors callback.
 * @details Enables or disables calling LibXML2 callback from the default
 * errors callback.
 * @param enabled the flag.
 */
void
xmlSecErrorsDefaultCallbackEnableOutput(int enabled) {
    xmlSecPrintErrorMessages = enabled;
}

/**
 * @brief Gets the known error code at position @p pos.
 * @param pos the error position.
 * @return the known error code or 0 if @p pos is greater than
 * total number of known error codes.
 */
int
xmlSecErrorsGetCode(xmlSecSize pos) {
    /* could not use asserts here! */
    if(pos < sizeof(xmlSecErrorsTable) / sizeof(xmlSecErrorsTable[0])) {
        return(xmlSecErrorsTable[pos].errorCode);
    }
    return(0);
}

/**
 * @brief Gets the known error message at position @p pos.
 * @param pos the error position.
 * @return the known error message or NULL if @p pos is greater than
 * total number of known error codes.
 */
const char*
xmlSecErrorsGetMsg(xmlSecSize pos) {
    /* could not use asserts here! */
    if(pos < sizeof(xmlSecErrorsTable) / sizeof(xmlSecErrorsTable[0])) {
        return(xmlSecErrorsTable[pos].errorMsg);
    }
    return(NULL);
}

/**
 * @brief Reports an error to the error callback.
 * @details Reports an error to the default (#xmlSecErrorsDefaultCallback) or
 * application specific callback installed using #xmlSecErrorsSetCallback
 * function.
 * @param file the error location filename (__FILE__).
 * @param line the error location line number (__LINE__).
 * @param func the error location function (__FUNCTION__).
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param errorSubject the error specific error subject (e.g. failed function name).
 * @param reason the error code.
 * @param msg the error message in printf format.
 * @param ... the parameters for the @p msg.
 */
void
xmlSecError(const char* file, int line, const char* func,
            const char* errorObject, const char* errorSubject,
            int reason, const char* msg, ...) {
    if(xmlSecErrorsClbk != NULL) {
        xmlChar error_msg[XMLSEC_ERRORS_BUFFER_SIZE];
        int ret;

        if(msg != NULL) {
            va_list va;

            va_start(va, msg);
            ret = xmlStrVPrintf(error_msg, sizeof(error_msg), msg, va);
            if(ret < 0) {
                /* Can't really report an error from an error callback */
                memcpy(error_msg, fatal_error, sizeof(fatal_error));
            }
            error_msg[sizeof(error_msg) - 1] = '\0'; /* just in case */
            va_end(va);
        } else {
            error_msg[0] = '\0';
        }
        xmlSecErrorsClbk(file, line, func, errorObject, errorSubject, reason, (char*)error_msg);
    }
}

/**
 * @brief Enables or disables the crypto library error log dump on exit.
 * @details Enables or disables the crypto library error log dump on exit (only supported by OpenSSL).
 * @param enabled the flag
 */
void
xmlSecErrorsPrintCryptoLibraryLogOnExitSet(int enabled) {
    gXmlSecErrorsPrintCryptoLibraryLogOnExitIsEnabled = enabled;
}

/**
 * @brief Returns 1 if the crypto library error log dump on exit is enabled.
 * @details Returns 1 if the crypto library error log dump on exit is enabled or 0 otherwise (only supported by OpenSSL).
 */
int
xmlSecErrorsPrintCryptoLibraryLogOnExitIsEnabled(void) {
    return(gXmlSecErrorsPrintCryptoLibraryLogOnExitIsEnabled);
}
