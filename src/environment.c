#define _GNU_SOURCE
#include <prettify/panic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <switch-netns/environment.h>

extern char** environ;

Environment Environment_get() {
    size_t entries_count = 0;

    for (size_t i = 0; environ != NULL && environ[i] != NULL; i++)
        entries_count++;

    char** pointers = (char**)calloc(entries_count + 1,
                                     sizeof(char*));  // +1 for NULL-terminator
    if (pointers == NULL) panic("Failed to allocate memory");
    pointers[entries_count] = NULL;

    // Clone data
    for (size_t i = 0; i < entries_count; i++) {
        const char* entry = environ[i];
        char* dup = strdup(entry);

        if (dup == NULL) panic("Failed to allocate memory");

        pointers[i] = dup;
    }

    return (Environment){
        .count = entries_count,
        .entries = pointers,
    };
}

void Environment_print(const Environment* env) {
    for (size_t i = 0; i < env->count; i++) {
        char* entry = env->entries[i];
        printf("%s\n", entry);
    }
}

void Environment_apply(Environment env) {
    clearenv();
    for (size_t i = 0; i < env.count; i++) {
        char* entry = env.entries[i];
        if (putenv(entry) != 0) {
            perror("putenv failed");
            panic("Could not restore environment variables.");
        }
    }
    free(env.entries);  // We moved all entries to environment, and now can free
                        // handles array.
}

void Environment_free(Environment env) {
    for (size_t i = 0; i < env.count; i++) {
        free(env.entries[i]);
    }
    free(env.entries);
}
