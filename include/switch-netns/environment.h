#ifndef SWITCH_NETNS_ENVIRONMENT_H_
#define SWITCH_NETNS_ENVIRONMENT_H_

#include <stdlib.h>

typedef struct {
    size_t count;
    char** entries;
} Environment;

Environment Environment_get();
void Environment_print(const Environment* env);
void Environment_apply(Environment env);
void Environment_free(Environment env);

#endif
