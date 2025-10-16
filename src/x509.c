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

#define XMLSEC_X509_NAME_READ_STATE_NORMAL          0
#define XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH1    1
#define XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH2    2
#define XMLSEC_X509_NAME_READ_STATE_DELIMETER       3

int
xmlSec509NameStringRead(const xmlChar **in, xmlSecSize *inSize,
                            xmlSecByte *out, xmlSecSize outSize, xmlSecSize *outWritten,
                            xmlSecByte delim, int ingoreTrailingSpaces
) {
    xmlSecByte inCh, inFirstHex = 0;
    xmlSecSize ii, jj, nonSpaceJJ;
    int state = XMLSEC_X509_NAME_READ_STATE_NORMAL;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2((*in) != NULL, -1);
    xmlSecAssert2(inSize != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    ii = jj = nonSpaceJJ = 0;
    while ((ii < (*inSize)) && (state != XMLSEC_X509_NAME_READ_STATE_DELIMETER)) {
        inCh = (*in)[ii];
        if (jj >= outSize) {
            xmlSecInvalidSizeOtherError("output buffer is too small", NULL);
            return(-1);
        }

        switch(state) {
        case XMLSEC_X509_NAME_READ_STATE_NORMAL:
            if (inCh == delim) {
                /* stop */
                state = XMLSEC_X509_NAME_READ_STATE_DELIMETER;
            } else if (inCh == '\\') {
                /* do not update output, move to next chat */
                state = XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH1;
                ++ii;
            } else {
                /* copy char and move to next */
                out[jj] = inCh;
                ++ii;
                ++jj;

                /* remember position of last non-spaceChar */
                if (ingoreTrailingSpaces && !isspace(inCh)) {
                    nonSpaceJJ = jj;
                }
            }
            break;
        case XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH1:
             /* if next char after \\ is a hex then we expect \\XX, otherwise we just remove \\ */
             if (xmlSecIsHex(inCh)) {
                inFirstHex = inCh;
                state = XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH2;
                ++ii;
             } else {
                /* just remove \\ */
                state = XMLSEC_X509_NAME_READ_STATE_NORMAL;

                /* copy char and move to next */
                out[jj] = inCh;
                ++ii;
                ++jj;

                /* remember position of last non-spaceChar */
                if (ingoreTrailingSpaces && !isspace(inCh)) {
                    nonSpaceJJ = jj;
                }
             }
            break;
        case XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH2:
            /* two XX chars are expected */
            if ((xmlSecIsHex(inCh)) && (inFirstHex > 0)) {
                state = XMLSEC_X509_NAME_READ_STATE_NORMAL;
                inCh = xmlSecFromHex2(inFirstHex, inCh);
                inFirstHex = 0;

                /* copy char and move to next */
                out[jj] = inCh;
                ++ii;
                ++jj;

                /* remember position of last non-spaceChar */
                if (ingoreTrailingSpaces && !isspace(inCh)) {
                    nonSpaceJJ = jj;
                }
            } else {
                xmlSecInvalidDataError("two hex digits expected", NULL);
                return(-1);
            }
            break;
        default:
            xmlSecInternalError2("", NULL, "invalid state while parsing name=%d", state);
            return(-1);
        }
    }

    /* success */

    (*inSize) -= ii;
    (*in) += ii;

    if (ingoreTrailingSpaces) {
        (*outWritten) = nonSpaceJJ;
    } else {
        (*outWritten) = (jj);
    }

    return(0);
}

#endif /* XMLSEC_NO_X509 */
