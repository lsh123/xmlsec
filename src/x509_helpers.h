/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Internal helper functions for X509 certificate processing.
 */
#ifndef XMLSEC_X509_HELPERS_H
#define XMLSEC_X509_HELPERS_H

#ifndef XMLSEC_NO_X509

#ifndef XMLSEC_PRIVATE
#error "x509_helpers.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-crypto libraries"
#endif /* XMLSEC_PRIVATE */

#include <xmlsec/xmlsec.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/x509.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/******************************************************************************
 *
 * Helper functions to read/write X509 Keys
 *
  *****************************************************************************/


/**
 * @brief Reads a key from X509 data value.
 * @param data the pointer to X509 key data
 * @param x509Value the pointer to input xmlSecKeyX509DataValue.
 * @param keysMngr the pointer to xmlSecKeysMngr.
 * @param flags the flags for certs processing.
 * @return 0 on success and a negative value otherwise.
 */
typedef int                    (*xmlSecKeyDataX509Read)                 (xmlSecKeyDataPtr data,
                                                                         xmlSecKeyX509DataValuePtr x509Value,
                                                                         xmlSecKeysMngrPtr keysMngr,
                                                                         unsigned int flags);

/**
 * @brief Writes the next X509 object (cert or crl) into x509Value.
 * @details If available, writes the next X509 object (cert or crl) into @p x509Value.
 * @param data the pointer to input xmlSecKeyData.
 * @param x509Value the pointer to result xmlSecKeyX509DataValue.
 * @param content the bitmask of what should be output to @p x509Value.
 * @param context the pointer to the writer function context.
 * @return 1 on success, 0 if no more certs/crls are available, or a negative value if an error occurs.
 */
typedef int                    (*xmlSecKeyDataX509Write)                (xmlSecKeyDataPtr data,
                                                                         xmlSecKeyX509DataValuePtr x509Value,
                                                                         int content,
                                                                         void* context);

XMLSEC_EXPORT int               xmlSecKeyDataX509XmlRead                (xmlSecKeyPtr key,
                                                                         xmlSecKeyDataPtr data,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         xmlSecKeyDataX509Read readFunc);
XMLSEC_EXPORT int               xmlSecKeyDataX509XmlWrite               (xmlSecKeyDataPtr data,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         int base64LineSize,
                                                                         int addLineBreaks,
                                                                         xmlSecKeyDataX509Write writeFunc,
                                                                         void* writeFuncContext);


#define XMLSEC_X509_MAX_SERIAL_NUMBER_BYTES     20  /* RFC 5280: max 20-octet DER INTEGER content (positive value, MSB=0 => max ~159-bit) */
#define XMLSEC_X509_MAX_SERIAL_NUMBER_CHARS     50  /* RFC 5280: conservative bound covering the full 160-bit range: ceil(20 * log10(256)) = 49 decimal digits + 1 for the NUL terminator (the actual max is 48 digits since the MSB is always 0) */

#define XMLSEC_X509_VALUE_TYPE_UTF8_STRING          0  /* the value is a string (empty, quoted, or plain) */
#define XMLSEC_X509_VALUE_TYPE_OCTET_STRING         1  /* the value is a hex-encoded octet string (prefixed with '#') */

typedef int             (*xmlSecX509NameReadCallback)   (const xmlSecByte* name,
                                                          const xmlSecByte* value,
                                                          xmlSecSize valueSize,
                                                           int type,
                                                          void* context);
typedef struct _xmlSecX509NameReplacements {
    const xmlChar * original;
    const xmlChar * replacement;
} xmlSecX509NameReplacements;

XMLSEC_EXPORT int       xmlSecX509NameRead              (const xmlChar *str,
                                                         xmlSecX509NameReplacements *replacements,
                                                         xmlSecX509NameReadCallback callback,
                                                         void * context);



XMLSEC_EXPORT int       xmlSecX509EscapedStringRead      (const xmlChar **in,
                                                         xmlSecSize *inSize,
                                                         xmlSecByte *out,
                                                         xmlSecSize outSize,
                                                         xmlSecSize *outWritten,
                                                         xmlSecByte delim,
                                                         int ignoreTrailingSpaces);

XMLSEC_EXPORT int       xmlSecX509AttrValueStringRead    (const xmlChar **in,
                                                         xmlSecSize *inSize,
                                                         xmlSecByte *out,
                                                         xmlSecSize outSize,
                                                         xmlSecSize *outWritten,
                                                         int *outType,
                                                         xmlSecByte delim,
                                                         int ignoreTrailingSpaces);

XMLSEC_EXPORT xmlChar*  xmlSecX509SerialNumberWrite      (const xmlSecByte *data,
                                                         xmlSecSize dataSize);

XMLSEC_EXPORT int       xmlSecX509SerialNumberRead       (const xmlChar *str,
                                                         xmlSecByte *res,
                                                         xmlSecSize resSize,
                                                         xmlSecSize *written);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_X509 */

#endif /* XMLSEC_X509_HELPERS_H */
