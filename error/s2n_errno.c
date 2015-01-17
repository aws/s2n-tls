#include <strings.h>
#include <stdlib.h>

#include "error/s2n_errno.h"

#include <s2n.h>

__thread int s2n_errno;
__thread const char *s2n_debug_str;

struct s2n_error_translation
{
    int errno_value;
    char * str;
};

struct s2n_error_translation EN[] = { { 0 }
};

const char *s2n_strerror(int error, const char *lang)
{
    const char *no_such_language = "Language is not supported for error translation";
    const char *no_such_error = "Internal s2n error";
    
    if (lang == NULL) {
        lang = "EN"; 
    }

    if (strcasecmp(lang, "EN")) {
        return no_such_language;
    }

    return no_such_error;
}
