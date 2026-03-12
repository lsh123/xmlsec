/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Internal header only used during the compilation,
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_X509_HELPERS_H__
#define __XMLSEC_X509_HELPERS_H__

#ifndef XMLSEC_NO_X509

#ifndef XMLSEC_PRIVATE
#error "x509_helpers.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */

#include <xmlsec/xmlsec.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/x509.h>

/**************************************************************************
 *
 * Helper functions to read/write X509 Keys
 *
 *************************************************************************/


/**
 * xmlSecKeyDataX509Read:
 * @data:               the pointer to X509 key data
 * @x509Value:          the pointer to input @xmlSecKeyX509DataValue.
 * @keysMngr:           the pointer to @xmlSecKeysMngr.
 * @flags:              the flags for certs processing.
 *
 *
 * Returns: 0 on success and a negative value otherwise.
 */
typedef int                    (*xmlSecKeyDataX509Read)                 (xmlSecKeyDataPtr data,
                                                                         xmlSecKeyX509DataValuePtr x509Value,
                                                                         xmlSecKeysMngrPtr keysMngr,
                                                                         unsigned int flags);

/**
 * xmlSecKeyDataX509Write:
 * @data:               the pointer to result @xmlSecKeyData.
 * @x509Value:          the pointer to result @xmlSecKeyX509DataValue.
 * @content:            the bitmask of what should be output to @x509Value.
 * @context:            the writer function context.
 *
 * If available, writes the next X509 object (cert or crl) into @x509Value.
 *
 * Returns: 1 on success, 0 if no more certs/crls are available, or a negative
 * value if an error occurs.
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
#define XMLSEC_X509_MAX_SERIAL_NUMBER_CHARS     50  /* RFC 5280: 20 bytes can hold at most ceil(20 * log10(256)) = 49 decimal digits; */

#define XMLSEC_X509_VALUE_TYPE_UF8_STRING           0
#define XMLSEC_X509_VALUE_TYPE_OCTET_STRING         1

typedef int             (*xmlSecX509NameReadCallback)   (const xmlChar * name,
                                                         const xmlChar * value,
                                                         xmlSecSize valueSize,
                                                         int type,
                                                         void * context);
typedef struct _xmlSecx509NameReplacements {
    const xmlChar * original;
    const xmlChar * replacement;
} xmlSecx509NameReplacements;

XMLSEC_EXPORT int       xmlSecX509NameRead              (const xmlChar *str,
                                                         xmlSecx509NameReplacements *replacements,
                                                         xmlSecX509NameReadCallback callback,
                                                         void * context);



XMLSEC_EXPORT int       xmlSecX509EscapedStringRead      (const xmlChar **in,
                                                         xmlSecSize *inSize,
                                                         xmlSecByte *out,
                                                         xmlSecSize outSize,
                                                         xmlSecSize *outWritten,
                                                         xmlSecByte delim,
                                                         int ingoreTrailingSpaces);

XMLSEC_EXPORT int       xmlSecX509AttrValueStringRead    (const xmlChar **in,
                                                         xmlSecSize *inSize,
                                                         xmlSecByte *out,
                                                         xmlSecSize outSize,
                                                         xmlSecSize *outWritten,
                                                         int *outType,
                                                         xmlSecByte delim,
                                                         int ingoreTrailingSpaces);

XMLSEC_EXPORT xmlChar*  xmlSecX509SerialNumberWrite      (const xmlSecByte *data,
                                                         xmlSecSize dataSize);

XMLSEC_EXPORT int       xmlSecX509SerialNumberRead       (const xmlChar *str,
                                                         xmlSecByte *res,
                                                         xmlSecSize resSize,
                                                         xmlSecSize *written);

#endif /* XMLSEC_NO_X509 */

#endif /* __XMLSEC_X509_HELPERS_H__ */
