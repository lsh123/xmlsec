/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/debug.h>

static clock_t totalTime = 0;
static clock_t startTime = 0;

void
xmlSecTimerInit(void) {
    totalTime = 0;
}

void
xmlSecTimerStart(void) {
    startTime = clock();
}

void
xmlSecTimerEnd(void) {
    totalTime += clock() - startTime; 
}

double
xmlSecTimerGet(void) {
    return((double)totalTime / (CLOCKS_PER_SEC / 1000));
}

