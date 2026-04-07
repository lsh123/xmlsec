/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_X509_H__
#define __XMLSEC_X509_H__

#include <xmlsec/buffer.h>

/**
 * @brief The content of a child of X509Data node.
 * @details The content of a child of &lt;X509Data/&gt; node. Not all values will be set!
 */
struct _xmlSecKeyX509DataValue {
    xmlSecBuffer cert;  /**< the certificate from &lt;dsig:X509Certificate/&gt; node. */
    xmlSecBuffer crl;  /**< the crl from &lt;dsig:X509CRL/&gt; node. */

    xmlSecBuffer ski;  /**< the ski from &lt;dsig:X509SKI/&gt; node. */

    xmlChar* subject;  /**< the subject name from <dsig:X509SubjectName /> node. */

    xmlChar* issuerName;  /**< the ski from &lt;dsig:X509IssuerSerial/&gt; node. */
    xmlChar* issuerSerial;  /**< the ski from &lt;dsig:X509IssuerSerial/&gt; node. */

    xmlChar* digestAlgorithm;  /**< the #digest algorithm from &lt;dsig11:X509Digest/&gt; node. */
    xmlSecBuffer digest;  /**< the digest from &lt;dsig11:X509Digest/&gt; node. */
};

#endif /* __XMLSEC_X509_H__ */
