/**
 *
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#if defined(_MSC_VER) && _MSC_VER < 1900
#define snprintf _snprintf
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>

#include <xmlsec/xmlsec.h>
#include "cmdline.h"

static int                      xmlSecAppCmdLineMatchParam      (const char* argvParam,
                                                                 const char* paramName,
                                                                 int canHaveNameString);
static xmlSecAppCmdLineParamPtr xmlSecAppCmdLineParamsListFind  (xmlSecAppCmdLineParamPtr* params,
                                                                 xmlSecAppCmdLineParamTopic topics,
                                                                 const char* name);
static int                      xmlSecAppCmdLineParamRead       (xmlSecAppCmdLineParamPtr param,
                                                                 const char** argv,
                                                                 int argc,
                                                                 int pos);
static int                      xmlSecAppCmdLineTimeParamRead   (const char* str,
                                                                 time_t* t,
                                                                 int is_gmt_time);

#if defined(_MSC_VER)
#define XMLSEC_MKGMTIME  _mkgmtime
#else /* defined(_MSC_VER) */
#define XMLSEC_MKGMTIME  xmlSecAppGetGmtTime

static time_t                   xmlSecAppGetGmtTime             (struct tm* timeptr);
#endif /* defined(_MSC_VER) */

int
xmlSecAppCmdLineParamIsSet(xmlSecAppCmdLineParamPtr param) {
    return(((param != NULL) && (param->value != NULL)) ? 1 : 0);
}

const char*
xmlSecAppCmdLineParamGetString(xmlSecAppCmdLineParamPtr param) {
    if(param->type != xmlSecAppCmdLineParamTypeString) {
        fprintf(stderr, "Error: parameter \"%s\" is not string.\n", param->fullName);
        return(NULL);
    }
    return((param->value != NULL) ? param->value->strValue : NULL);
}

const char*
xmlSecAppCmdLineParamGetStringList(xmlSecAppCmdLineParamPtr param) {
    if(param->type != xmlSecAppCmdLineParamTypeStringList) {
        fprintf(stderr, "Error: parameter \"%s\" is not string list.\n", param->fullName);
        return(NULL);
    }
    return((param->value != NULL) ? param->value->strListValue : NULL);
}

int
xmlSecAppCmdLineParamGetInt(xmlSecAppCmdLineParamPtr param, int def) {
    if(param->type != xmlSecAppCmdLineParamTypeNumber) {
        fprintf(stderr, "Error: parameter \"%s\" is not integer.\n", param->fullName);
        return(def);
    }
    return((param->value != NULL) ? param->value->intValue : def);
}

time_t
xmlSecAppCmdLineParamGetTime(xmlSecAppCmdLineParamPtr param, time_t def) {
    if((param->type != xmlSecAppCmdLineParamTypeTime) && (param->type != xmlSecAppCmdLineParamTypeGmtTime)) {
        fprintf(stderr, "Error: parameter \"%s\" is not time.\n", param->fullName);
        return(def);
    }
    return((param->value != NULL) ? param->value->timeValue : def);
}

int
xmlSecAppCmdLineParamsListParse(xmlSecAppCmdLineParamPtr* params,
                                xmlSecAppCmdLineParamTopic topics,
                                const char** argv, int argc, int pos) {
    xmlSecAppCmdLineParamPtr param;
    int ii;
    int ret;

    assert(params != NULL);
    assert(argv != NULL);

    while((pos < argc) && (argv[pos][0] == '-') && (strcmp(argv[pos], XMLSEC_STDOUT_FILENAME) != 0)) {
        param = xmlSecAppCmdLineParamsListFind(params, topics, argv[pos]);
        if(param == NULL) {
            fprintf(stderr, "Error: parameter \"%s\" is not supported or the requested\nfeature might have been disabled during compilation.\n", argv[pos]);
            return(-1);
        }

        ret = xmlSecAppCmdLineParamRead(param, argv, argc, pos);
        if(ret < pos) {
            fprintf(stderr, "Error: failed to parse parameter \"%s\".\n", argv[pos]);
            return(-1);
        }
        pos = ret + 1;
    }

    /* check that all parameters at the end are filenames */
    for(ii = pos; (ii < argc); ++ii) {
        if((argv[ii][0] == '-') && (strcmp(argv[ii], XMLSEC_STDOUT_FILENAME) != 0)) {
            fprintf(stderr, "Error: filename is expected instead of parameter \"%s\".\n", argv[ii]);
            return(-1);
        }
    }

    /* done */
    return(pos);
}

void
xmlSecAppCmdLineParamsListClean(xmlSecAppCmdLineParamPtr* params) {
    xmlSecAppCmdLineValuePtr tmp;
    size_t i;

    assert(params != NULL);

    for(i = 0; params[i] != NULL; ++i) {
        while(params[i]->value != NULL) {
            tmp = params[i]->value;
            params[i]->value = params[i]->value->next;
            xmlSecAppCmdLineValueDestroy(tmp);
        }
    }
}

void
xmlSecAppCmdLineParamsListPrint(xmlSecAppCmdLineParamPtr* params,
                                xmlSecAppCmdLineParamTopic topics,
                                FILE* output) {
    size_t i;

    assert(params != NULL);
    assert(output != NULL);

    for(i = 0; params[i] != NULL; ++i) {
        if(((params[i]->topics & topics) != 0) && (params[i]->help != NULL)) {
            fprintf(output, "  %s\n", params[i]->help);
        }
    }
}

xmlSecAppCmdLineValuePtr
xmlSecAppCmdLineValueCreate(xmlSecAppCmdLineParamPtr param, int pos) {
    xmlSecAppCmdLineValuePtr value;

    assert(param != NULL);
    value = (xmlSecAppCmdLineValuePtr) malloc(sizeof(xmlSecAppCmdLineValue));
    if(value == NULL) {
        fprintf(stderr, "Error: malloc failed (" XMLSEC_SIZE_T_FMT " bytes).\n",
            sizeof(xmlSecAppCmdLineValue));
        return(NULL);
    }
    memset(value, 0, sizeof(xmlSecAppCmdLineValue));

    value->param = param;
    value->pos = pos;
    return(value);
}

void
xmlSecAppCmdLineValueDestroy(xmlSecAppCmdLineValuePtr value) {
    assert(value != NULL);

    if(value->strListValue != NULL) {
        free((void*)value->strListValue);
    }
    free(value);
}

static int
xmlSecAppCmdLineMatchParam(const char* argvParam, const char* paramName,
                           int canHaveNameString) {
    assert(argvParam != NULL);
    assert(paramName != NULL);

    if(canHaveNameString != 0) {
        size_t len = strlen(paramName);
        if((strncmp(argvParam, paramName, len) == 0) &&
           ((argvParam[len] == '\0') || (argvParam[len] == ':'))) {

           return(1);
        }
    } else if(strcmp(argvParam, paramName) == 0) {
        return(1);
    }
    return(0);
}

static xmlSecAppCmdLineParamPtr
xmlSecAppCmdLineParamsListFind(xmlSecAppCmdLineParamPtr* params, xmlSecAppCmdLineParamTopic topics,
                                const char* name) {
    size_t i;
    int canHaveNameString;

    assert(params != NULL);
    assert(name != NULL);

    for(i = 0; params[i] != NULL; ++i) {
        if((params[i]->topics & topics) == 0) {
            continue;
        }

        canHaveNameString = ((params[i]->flags & xmlSecAppCmdLineParamFlagParamNameValue) != 0) ? 1 : 0;
        if((params[i]->fullName != NULL) &&
           (xmlSecAppCmdLineMatchParam(name, params[i]->fullName, canHaveNameString) == 1)) {

            return(params[i]);
        }

        if((params[i]->shortName != NULL) &&
           (xmlSecAppCmdLineMatchParam(name, params[i]->shortName, canHaveNameString) == 1)) {

            return(params[i]);
        }
    }

    return(NULL);
}

static int
xmlSecAppCmdLineParamRead(xmlSecAppCmdLineParamPtr param, const char** argv, int argc, int pos) {
    xmlSecAppCmdLineValuePtr value;
    xmlSecAppCmdLineValuePtr prev = NULL;
    char* buf;

    assert(param != NULL);
    assert(argv != NULL);
    assert(pos < argc);

    /* first find the previous value in the list */
    if((param->flags & xmlSecAppCmdLineParamFlagMultipleValues) != 0) {
        prev = param->value;
        while((prev != NULL) && (prev->next != NULL)) {
            prev = prev->next;
        }
    } else if(param->value != NULL) {
        fprintf(stderr, "Error: only one parameter \"%s\" is allowed.\n", argv[pos]);
        return(-1);
    }

    /* create new value and add to the list */
    value = xmlSecAppCmdLineValueCreate(param, pos);
    if(value == NULL) {
        fprintf(stderr, "Error: failed to create value for parameter \"%s\".\n", argv[pos]);
        return(-1);
    }
    if(prev != NULL) {
        assert(prev->next == NULL);
        prev->next = value;
    } else {
        param->value = value;
    }

    /* if we can have a string value after the name, parse it */
    if((param->flags & xmlSecAppCmdLineParamFlagParamNameValue) != 0) {
        value->paramNameValue = strchr(argv[pos], ':');
        if(value->paramNameValue != NULL) {
            ++value->paramNameValue;
        }
    }

    switch(param->type) {
        case xmlSecAppCmdLineParamTypeFlag:
            /* do nothing */
            break;
        case xmlSecAppCmdLineParamTypeString:
            if(pos + 1 >= argc) {
                fprintf(stderr, "Error: string argument expected for parameter \"%s\".\n", argv[pos]);
                return(-1);
            }
            value->strValue = argv[++pos];
            break;
        case xmlSecAppCmdLineParamTypeStringList:
            if(pos + 1 >= argc) {
                fprintf(stderr, "Error: string list argument expected for parameter \"%s\".\n",
                    argv[pos]);
                return(-1);
            }
            value->strValue = argv[++pos];
            buf = (char*)malloc(strlen(value->strValue) + 2);
            if(buf == NULL) {
                fprintf(stderr, "Error: failed to allocate memory (" XMLSEC_SIZE_T_FMT " bytes).\n",
                    strlen(value->strValue) + 2);
                return(-1);
            }
            memset(buf, 0, strlen(value->strValue) + 2);
            memcpy(buf, value->strValue, strlen(value->strValue));
            value->strListValue = buf;
            while((*buf) != '\0') {
                if((*buf) == ',') {
                    (*buf) = '\0';
                }
                ++buf;
            }
            break;
        case xmlSecAppCmdLineParamTypeNumber:
            if(pos + 1 >= argc) {
                fprintf(stderr, "Error: integer argument expected for parameter \"%s\".\n", argv[pos]);
                return(-1);
            }
            value->strValue = argv[++pos];
            {
                char* end = NULL;
                long v;

                errno = 0;
                v = strtol(value->strValue, &end, 10);
                if((end == value->strValue) || (*end != '\0') || (errno == ERANGE) ||
                   (v < INT_MIN) || (v > INT_MAX)) {
                    fprintf(stderr, "Error: integer argument \"%s\" is invalid.\n", value->strValue);
                    return(-1);
                }
                value->intValue = (int)v;
            }
            break;
        case xmlSecAppCmdLineParamTypeTime:
            if(pos + 1 >= argc) {
                fprintf(stderr, "Error: time argument expected for parameter \"%s\".\n", argv[pos]);
                return(-1);
            }
            value->strValue = argv[++pos];
            if(xmlSecAppCmdLineTimeParamRead(value->strValue, &(value->timeValue), 0) < 0) {
                fprintf(stderr, "Error: time argument \"%s\" is invalid, expected format is \"YYYY-MM-DD HH:MM:SS\" (or \"YYYY-MM-DD+HH:MM:SS\").\n", value->strValue);
                return(-1);
            }
            break;
        case xmlSecAppCmdLineParamTypeGmtTime:
            if(pos + 1 >= argc) {
                fprintf(stderr, "Error: gmt time argument expected for parameter \"%s\".\n", argv[pos]);
                return(-1);
            }
            value->strValue = argv[++pos];
            if(xmlSecAppCmdLineTimeParamRead(value->strValue, &(value->timeValue), 1) < 0) {
                fprintf(stderr, "Error: gmt time argument \"%s\" is invalid, expected format is \"YYYY-MM-DD HH:MM:SS\" (or \"YYYY-MM-DD+HH:MM:SS\").\n", value->strValue);
                return(-1);
            }
            break;
    }
    return(pos);
}

#if !defined(_MSC_VER)
static time_t
xmlSecAppGetGmtTime(struct tm* timeptr) {
    time_t t1, t2;
    struct tm* tmGmt;

    if(timeptr == NULL) {
        return(0);
    }

    /* t1 is gmt time "mapped" to localtime as-is */
    t1 = mktime(timeptr);
    if(t1 == (time_t)-1) {
        return((time_t)-1);
    }

    /* t2 is "mapped" gmt time converted to gmt */
    tmGmt = gmtime(&t1);
    if(tmGmt == NULL) {
        return((time_t)-1);
    }
    /* gmtime() resets tm_isdst to 0, which would make mktime() below assume
     * standard (non-DST) time and apply the standard offset even when t1
     * falls during DST.  Force a re-resolution of the DST state
     * (tm_isdst = -1) so that the (t2 - t1) delta reflects the actual UTC
     * offset; otherwise the result is off by up to one hour when a DST
     * transition falls between the two mktime() conversions. */
    tmGmt->tm_isdst = -1;
    t2 = mktime(tmGmt);
    if(t2 == (time_t)-1) {
        return((time_t)-1);
    }

    /* shift t1 back by the (t2 - t1) delta */
    return(t1 - (t2 - t1));
}
#endif /* !defined(_MSC_VER) */

/*
 * Read a decimal field of at most `maxCount` digits from `*p` (advancing
 * it past the field) into `*out`.  At least one digit is required; a field
 * with more than `maxCount` digits is rejected (rather than silently
 * truncated, as "%Nd" in sscanf() would do, e.g. "099" -> 9).
 */
static int
xmlSecAppTimeParseDigits(const char** p, int maxCount, int* out) {
    int value = 0;
    int i;

    if((p == NULL) || (out == NULL) || (maxCount <= 0)) {
        return(-1);
    }
    for(i = 0; i < maxCount; i++) {
        char c = (**p);

        if((c < '0') || (c > '9')) {
            break;
        }
        value = (value * 10) + (c - '0');
        (*p)++;
    }
    if(i == 0) {
        /* no digits at all */
        return(-1);
    }
    if((**p >= '0') && (**p <= '9')) {
        /* more digits follow: the value would be silently truncated */
        return(-1);
    }
    *out = value;
    return(0);
}

static int
xmlSecAppCmdLineTimeParamRead(const char* str, time_t* t, int is_gmt_time) {
    struct tm tm;
    const char* p;

    if((str == NULL) || (t == NULL)) {
        return(-1);
    }
    memset(&tm, 0, sizeof(tm));
    tm.tm_isdst = -1;

    /* Parse "YYYY-MM-DD HH:MM:SS" (or "YYYY-MM-DD+HH:MM:SS") with strict
     * field validation.  The old sscanf() call neither checked for trailing
     * garbage (so "2024-01-02 03:04:05XYZ" was accepted) nor rejected
     * over-long fields (which "%2d" truncated silently).  Here every
     * separator must match exactly (whitespace between the date and the
     * time or a single "+", the format used by the test suite) and only
     * whitespace may follow the seconds. */
    p = str;
    if(xmlSecAppTimeParseDigits(&p, 4, &tm.tm_year) < 0) {
        return(-1);
    }
    if(*p != '-') {
        return(-1);
    }
    p++;
    if(xmlSecAppTimeParseDigits(&p, 2, &tm.tm_mon) < 0) {
        return(-1);
    }
    if(*p != '-') {
        return(-1);
    }
    p++;
    if(xmlSecAppTimeParseDigits(&p, 2, &tm.tm_mday) < 0) {
        return(-1);
    }
    if(*p == '+') {
        p++;
    } else {
        if(!((*p == ' ') || (*p == '\t'))) {
            return(-1);
        }
        while((*p == ' ') || (*p == '\t')) {
            p++;
        }
    }
    if(xmlSecAppTimeParseDigits(&p, 2, &tm.tm_hour) < 0) {
        return(-1);
    }
    if(*p != ':') {
        return(-1);
    }
    p++;
    if(xmlSecAppTimeParseDigits(&p, 2, &tm.tm_min) < 0) {
        return(-1);
    }
    if(*p != ':') {
        return(-1);
    }
    p++;
    if(xmlSecAppTimeParseDigits(&p, 2, &tm.tm_sec) < 0) {
        return(-1);
    }
    while(*p != '\0') {
        if(!((*p == ' ') || (*p == '\t'))) {
            return(-1);
        }
        p++;
    }

    if((tm.tm_year < 1900)
      || (tm.tm_mon  < 1) || (tm.tm_mon  > 12)
      || (tm.tm_mday < 1) || (tm.tm_mday > 31)
      || (tm.tm_hour < 0) || (tm.tm_hour > 23)
      || (tm.tm_min  < 0) || (tm.tm_min  > 59)
      || (tm.tm_sec  < 0) || (tm.tm_sec  > 61)) {
        return(-1);
    }

    /* reject impossible dates (e.g. 2024-02-30); mktime() would
     * silently normalize them to a date in the next month */
    {
        static const int daysInMonth[] = {31, 28, 31, 30, 31, 30,
                                          31, 31, 30, 31, 30, 31};
        int isLeap;
        int maxDay;

        isLeap = (((tm.tm_year % 4) == 0) && ((tm.tm_year % 100) != 0))
                     || ((tm.tm_year % 400) == 0);
        maxDay = daysInMonth[tm.tm_mon - 1];
        if((tm.tm_mon == 2) && isLeap) {
            maxDay = 29;
        }
        if(tm.tm_mday > maxDay) {
            return(-1);
        }
    }

    tm.tm_year -= 1900; /* tm relative format year */
    tm.tm_mon  -= 1; /* tm relative format month */

    if(is_gmt_time != 0) {
        (*t) = XMLSEC_MKGMTIME(&tm);
    } else {
        (*t) = mktime(&tm);
    }
    /* mktime()/XMLSEC_MKGMTIME() returns -1 for out-of-range dates;
     * the parsed year is always >= 1900 so -1 cannot be a valid
     * result here */
    if(*t == (time_t)-1) {
        return(-1);
    }
    return(0);
}
