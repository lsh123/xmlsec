/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Internal XSLT helper functions.
 */
#ifndef XMLSEC_XSLT_H
#define XMLSEC_XSLT_H

#ifndef XMLSEC_PRIVATE
#error "xslt.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-crypto libraries"
#endif /* XMLSEC_PRIVATE */

#ifndef XMLSEC_NO_XSLT

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int  xmlSecTransformXsltInitialize                           (void);
void xmlSecTransformXsltShutdown                             (void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_XSLT */

#endif /* XMLSEC_XSLT_H */
