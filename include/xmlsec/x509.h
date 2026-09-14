/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef XMLSEC_X509_H
#define XMLSEC_X509_H

/**
 * @defgroup xmlsec_core_x509 X509 Data
 * @ingroup xmlsec_core
 * @brief X509 data structures.
 * @{
 */

#include <xmlsec/buffer.h>

/**
 * @brief The content of a child of X509Data node.
 * @details The content of a child of &lt;X509Data/&gt; node. Not all values will be set!
 * The structure (and its members) are allocated and freed by the caller;
 * a caller that builds a value for the public find APIs (e.g.
 * #xmlSecKeysMngrFindKeyFromX509Data, #xmlSecKeyStoreFindKeyFromX509Data)
 * owns the structure and all of its members (the buffers and the
 * xmlChar* strings) and must free them.
 */
struct _xmlSecKeyX509DataValue {
    xmlSecBuffer cert;  /**< the certificate from &lt;dsig:X509Certificate/&gt; node. */
    xmlSecBuffer crl;  /**< the crl from &lt;dsig:X509CRL/&gt; node. */

    xmlSecBuffer ski;  /**< the ski from &lt;dsig:X509SKI/&gt; node. */

    xmlChar* subject;  /**< the subject name from &lt;dsig:X509SubjectName/&gt; node. */

    xmlChar* issuerName;  /**< the issuer name from &lt;dsig:X509IssuerName/&gt; node. */
    xmlChar* issuerSerial;  /**< the serial number from &lt;dsig:X509SerialNumber/&gt; node. */

    xmlChar* digestAlgorithm;  /**< the digest algorithm URI from the Algorithm attribute of &lt;dsig11:X509Digest/&gt; node. */
    xmlSecBuffer digest;  /**< the digest from &lt;dsig11:X509Digest/&gt; node. */
};

/**
 * @brief The X.509 key data value.
 */
typedef struct _xmlSecKeyX509DataValue                  xmlSecKeyX509DataValue;

/**
 * @brief Pointer to #_xmlSecKeyX509DataValue.
 */
typedef struct _xmlSecKeyX509DataValue                  *xmlSecKeyX509DataValuePtr;

/** @} */ /* xmlsec_core_x509 */

#endif /* XMLSEC_X509_H */
