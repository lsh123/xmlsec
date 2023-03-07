/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_X509_H__
#define __XMLSEC_X509_H__

/**
 * xmlSecKeyX509DataValue:
 * @cert:              the certificate from &lt;dsig:X509Certificate/&gt; node.
 * @crl:               the crl from &lt;dsig:X509CRL/&gt; node.
 * @ski:               the ski from &lt;dsig:X509SKI/&gt; node.
 * @subject:           the subject name from <dsig:X509SubjectName /> node.
 * @issuerName:        the ski from &lt;dsig:X509IssuerSerial/&gt; node.
 * @issuerSerial:      the ski from &lt;dsig:X509IssuerSerial/&gt; node.
 * @digestAlgorithm:   the @digest algorithm from &lt;dsig11:X509Digest/&gt; node.
 * @digest:            the digest from &lt;dsig11:X509Digest/&gt; node.
 *
 * The content of a child of <X509Data/> node. Not all values will be set!
 */
struct _xmlSecKeyX509DataValue {
    xmlSecBuffer cert;
    xmlSecBuffer crl;

    xmlSecBuffer ski;

    xmlChar* subject;

    xmlChar* issuerName;
    xmlChar* issuerSerial;

    xmlChar* digestAlgorithm;
    xmlSecBuffer digest;
};

#endif /* __XMLSEC_X509_H__ */
