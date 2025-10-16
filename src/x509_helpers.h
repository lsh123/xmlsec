/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Internal header only used during the compilation,
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
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

XMLSEC_EXPORT int       xmlSec509NameStringRead         (const xmlChar **in,
                                                         xmlSecSize *inSize,
                                                         xmlSecByte *out,
                                                         xmlSecSize outSize,
                                                         xmlSecSize *outWritten,
                                                         xmlSecByte delim,
                                                         int ingoreTrailingSpaces);

#endif /* XMLSEC_NO_X509 */

#endif /* __XMLSEC_X509_HELPERS_H__ */
