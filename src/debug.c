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

/**
 * xmlSecTimerInit:
 *
 * Resets the total time counter.
 */
void
xmlSecTimerInit(void) {
    totalTime = 0;
}

/**
 * xmlSecTimerStart:
 *
 * Starts timer.
 */
void
xmlSecTimerStart(void) {
    startTime = clock();
}

/**
 * xmlSecTimerEnd:
 *
 * Adds the time from the last xmlSecTimerStart() function call 
 * to the total time counter.
 */
void
xmlSecTimerEnd(void) {
    totalTime += clock() - startTime; 
}

/**
 * xmlSecTimerGet:
 *
 * Gets the current total time counter value in msec.
 *
 * Returns the current total time in msec.
 */ 
double
xmlSecTimerGet(void) {
    return((double)totalTime / (CLOCKS_PER_SEC / 1000));
}

