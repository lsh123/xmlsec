/** 
 *
 * XMLSec library
 * 
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#include "cmdline.h"

static int			xmlSecAppCmdLineMatchParam	(const char* argvParam,
								 const char* paramName,
								 int canHaveNameString);
static xmlSecAppCmdLineParamPtr	xmlSecAppCmdLineParamsListFind	(xmlSecAppCmdLineParamPtr* params,
								 xmlSecAppCmdLineParamTopic topics,
								 const char* name);
static int			xmlSecAppCmdLineParamRead	(xmlSecAppCmdLineParamPtr param,
								 const char** argv, 
								 int argc, 
								 int pos);
static int  			xmlSecAppCmdLineTimeParamRead	(const char* str, 
								 time_t* t);

int 
xmlSecAppCmdLineParamsListParse(xmlSecAppCmdLineParamPtr* params,
				xmlSecAppCmdLineParamTopic topics,
				const char** argv, int argc, int pos) {
    xmlSecAppCmdLineParamPtr param;
    int ret;
    
    assert(params != NULL);
    assert(argv != NULL);
    
    while((pos < argc) && (argv[pos][0] == '-')) {
	param = xmlSecAppCmdLineParamsListFind(params, topics, argv[pos]);
	if(param == NULL) {
	    fprintf(stderr, "Error: parameter \"%s\" is not valid.\n", argv[pos]);
	    return(-1);
	}
	
	ret = xmlSecAppCmdLineParamRead(param, argv, argc, pos);
	if(ret < pos) {
	    fprintf(stderr, "Error: failed to parse parameter \"%s\".\n", argv[pos]);
	    return(-1);
	}
	++pos;
    }
    
    return(pos);
}

void 
xmlSecAppCmdLineParamsListClean(xmlSecAppCmdLineParamPtr* params) {
    xmlSecAppCmdLineValuePtr tmp;
    size_t i;
    
    assert(params != NULL);
    
    for(i = 0; params[i] != NULL; ++i) {
	while(params[i]->values != NULL) {
	    tmp = params[i]->values;
	    params[i]->values = params[i]->values->next;
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
	fprintf(stderr, "Error: malloc failed (%d bytes).\n", sizeof(xmlSecAppCmdLineValue));
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
    
    free(value);
}

static int 
xmlSecAppCmdLineMatchParam(const char* argvParam, const char* paramName,
			   int canHaveNameString) {
    assert(argvParam != NULL);
    assert(paramName != NULL);
    
    if(canHaveNameString != 0) {
	int len = strlen(paramName);
	
	if((strncmp(argvParam, paramName, len) == 0) &&
	   ((argvParam[len] == ':') || (argvParam[len] == ':'))) {
	   
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
    
    assert(param != NULL);
    assert(argv != NULL);
    assert(pos < argc);
    
    /* first find the previous value in the list */
    if((param->flags & xmlSecAppCmdLineParamFlagMultipleValues) != 0) {
	prev = param->values; 
	while((prev != NULL) && (prev->next != NULL)) {
	    prev = prev->next; 
	}
    } else if(param->values != NULL) {
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
	param->values = value;
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
	    ++pos;
	    break;
	case xmlSecAppCmdLineParamTypeString:
	    if(pos + 1 >= argc) {
	        fprintf(stderr, "Error: string argument expected for parameter \"%s\".\n", argv[pos]);
	        return(-1);
	    }
	    value->strValue = argv[++pos];
	    break;
	case xmlSecAppCmdLineParamTypeNumber:
	    if(pos + 1 >= argc) {
	        fprintf(stderr, "Error: integer argument expected for parameter \"%s\".\n", argv[pos]);
	        return(-1);
	    }    
	    value->strValue = argv[++pos];
	    if(sscanf(value->strValue, "%d", &(value->intValue)) != 1) {
	        fprintf(stderr, "Error: integer argument \"%s\" is invalid.\n", value->strValue);
	        return(-1);
	    }    
	    break;
	case xmlSecAppCmdLineParamTypeTime:
	    if(pos + 1 >= argc) {
	        fprintf(stderr, "Error: time argument expected for parameter \"%s\".\n", argv[pos]);
	        return(-1);
	    }
	    value->strValue = argv[++pos];
	    if(xmlSecAppCmdLineTimeParamRead(value->strValue, &(value->timeValue)) < 0) {
	        fprintf(stderr, "Error: time argument \"%s\" is invalid, expected format is \"YYYY-MM-DD HH:MM:SS\").\n", value->strValue);
	        return(-1);
	    }    
	    break;
    }
    return(pos);
}

static int  
xmlSecAppCmdLineTimeParamRead(const char* str, time_t* t) {
    struct tm tm;
    int n;
    
    if((str == NULL) || (t == NULL)) {
	return(-1);
    }
    memset(&tm, 0, sizeof(tm));
    tm.tm_isdst = -1;
    
    n = sscanf(str, "%4d-%2d-%2d%*c%2d:%2d:%2d", 
			    &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
			    &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    if((n != 6) || (tm.tm_year < 1900) 
		|| (tm.tm_mon  < 1) || (tm.tm_mon  > 12) 
		|| (tm.tm_mday < 1) || (tm.tm_mday > 31)
		|| (tm.tm_hour < 0) || (tm.tm_hour > 23)
		|| (tm.tm_min  < 0) || (tm.tm_min  > 59)
		|| (tm.tm_sec  < 0) || (tm.tm_sec  > 61)) {
	return(-1);	    
    }

    tm.tm_year -= 1900; /* tm relative format year */
    tm.tm_mon  -= 1; /* tm relative format month */

    (*t) = mktime(&tm);
    return(0);    
}

