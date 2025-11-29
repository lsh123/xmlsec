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


#ifndef XMLSEC_PRIVATE
#error "x509_helpers.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */

#include <xmlsec/xmlsec.h>

#ifndef XMLSEC_NO_X509

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

#endif /* XMLSEC_NO_X509 */

#endif /* __XMLSEC_X509_HELPERS_H__ */
