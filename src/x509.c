/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Transform object functions.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#include "globals.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include "x509_helpers.h"


#ifndef XMLSEC_NO_X509

int
xmlSec509NameStringRead(const xmlChar **in, xmlSecSize *inSize,
                            xmlSecByte *out, xmlSecSize outSize,
                            xmlSecSize *outWritten,
                            xmlSecByte delim, int ingoreTrailingSpaces) {
    xmlSecSize ii, jj, nonSpace;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2((*in) != NULL, -1);
    xmlSecAssert2(inSize != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    ii = jj = nonSpace = 0;
    while (ii < (*inSize)) {
        xmlSecByte inCh, inCh2, outCh;

        inCh = (*in)[ii];
        if (inCh == delim) {
            break;
        }
        if (jj >= outSize) {
            xmlSecInvalidSizeOtherError("output buffer is too small", NULL);
            return(-1);
        }

        if (inCh == '\\') {
            /* try to move to next char after \\ */
            ++ii;
            if (ii >= (*inSize)) {
                break;
            }
            inCh = (*in)[ii];

            /* if next char after \\ is a hex then we expect \\XX, otherwise we just remove \\ */
            if (xmlSecIsHex(inCh)) {
                /* try to move to next char after \\X */
                ++ii;
                if (ii >= (*inSize)) {
                    xmlSecInvalidDataError("two hex digits expected", NULL);
                    return(-1);
                }
                inCh2 = (*in)[ii];
                if (!xmlSecIsHex(inCh2)) {
                    xmlSecInvalidDataError("two hex digits expected", NULL);
                    return(-1);
                }
                outCh = xmlSecFromHex2(inCh, inCh2);
            } else {
                outCh = inCh;
            }
        } else {
            outCh = inCh;
        }

        out[jj] = outCh;
        ++ii;
        ++jj;

        if (ingoreTrailingSpaces && !isspace(outCh)) {
            nonSpace = jj;
        }
    }

    (*inSize) -= ii;
    (*in) += ii;

    if (ingoreTrailingSpaces) {
        (*outWritten) = nonSpace;
    } else {
        (*outWritten) = (jj);
    }
    return(0);
}

#endif /* XMLSEC_NO_X509 */