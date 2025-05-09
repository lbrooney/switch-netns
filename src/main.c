#define _GNU_SOURCE
#include <cmdline.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <prettify/misc.h>
#include <prettify/panic.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <switch-netns/environment.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <unistd.h>

#include "prettify/assert.h"

// Prints human-readable messages and exits if any of required capabilities are
// missing.
static void check_capabilities(int* required_caps, size_t count,
                               const char* program_name);

static char* get_executable_path(const char* program_name);

typedef struct {
    int namespace_fd;
    int argc;
    char* const* argv;
} LaunchParams;

static LaunchParams parse_launch_params(const char* program_name, int argc,
                                        char** argv);

static void show_usage(const char* program_name);

static const char* get_setns_errno_description(int errno_number);

int main(int argc, char** argv) {
    const char* program_name = argv[0];

    // 1. Clear environment.
    Environment env = Environment_get();
    clearenv();

    // 2. Check that we have capabilities.
    cap_value_t required_caps[] = {CAP_SYS_ADMIN, CAP_SYS_PTRACE};
    check_capabilities(required_caps, LEN(required_caps), program_name);

    // 3. Parse cmdline.
    LaunchParams params = parse_launch_params(program_name, argc, argv);
    if (params.argc == 0) {
        fprintf(stderr, "No command provided.\n\n");
        show_usage(program_name);
        exit(2);
    }

    // 4. Switch network namespace.
    if (setns(params.namespace_fd, CLONE_NEWNET) != 0) {
        const char* setns_error_description = get_setns_errno_description(errno);
        perror("failed to set network namespace");

        if (setns_error_description)
            fprintf(stderr, "`setns()` failed: %s", setns_error_description);
        
        exit(3);
    }
    if (close(params.namespace_fd) != 0) {
        perror("failed to close namespace file");
        exit(4);
    }

    // 6. Execute user-provided command.
    execvpe(params.argv[0], params.argv, env.entries);

    perror("execve failed; could not execute user program");
    exit(5);
}

static void show_usage(const char* program_name) {
    fprintf(stderr, "Usage: %s [--by-name my_ns] -- <command> <args...>\n",
            program_name);
}

static int find_dash(int argc, const char* const* argv) {
    for (int i = 0; i < argc; i++) {
        if (strcmp("--", argv[i]) == 0) return i;
    }
    return -1;
}

static LaunchParams parse_launch_params(const char* program_name, int argc,
                                        char** argv) {
    int dash_position = find_dash(argc, (const char* const*)argv);

    int cmdline_argc = dash_position >= 0 ? dash_position : argc;
    struct gengetopt_args_info args_info;
    if (cmdline_parser(cmdline_argc, argv, &args_info) != 0) {
        show_usage(program_name);
        exit(6);
    }

    if (dash_position < 0) {
        return (LaunchParams){
            .namespace_fd = -1,
            .argc = 0,
            .argv = NULL,
        };
    }

    char* filepath = NULL;

    if (args_info.by_file_given) {
        filepath = strdup(args_info.by_file_arg);
        assert_alloc(filepath);
    } else if (args_info.by_name_given) {
        // ==== BY NAME ====
        const char* netns_name = args_info.by_name_arg;

        size_t needed_len = strlen("/run/netns/%s") + strlen(netns_name) + 1;
        filepath = (char*)calloc(needed_len, sizeof(char));
        assert_alloc(filepath);
        snprintf(filepath, needed_len - 1, "/run/netns/%s", netns_name);
    } else if (args_info.by_pid_given) {
        long pid = args_info.by_pid_arg;

        char buffer[2048] = "\0";
        snprintf(buffer, LEN(buffer) - 1, "/proc/%ld", pid);

        filepath = strdup(buffer);
        assert_alloc(filepath);
    } else {
        fprintf(stderr,
                "No network namespace resolution way (`--by-name`, "
                "`--by-file`, or `--by-pid`) provided.");
        show_usage(program_name);
        exit(7);
    }

    if (filepath == NULL)
        panic(
            "Internal error: Failed to establish filepath of network "
            "namespace.")

            int namespace_fd = open(filepath, O_RDONLY);
    free(filepath);
    if (namespace_fd < 0) {
        perror("open failed; could not open namespace file");
        fprintf(stderr, "Could not open file '%s'.", args_info.by_file_arg);
        exit(8);
    }

    return (LaunchParams){
        .namespace_fd = namespace_fd,
        .argc = argc - dash_position - 1,
        .argv = &argv[dash_position + 1],
    };
}

static void check_capabilities(cap_value_t* required_caps, size_t count,
                               const char* program_name) {
    cap_t capabilities = cap_get_proc();
    if (!capabilities) {
        perror(
            "cap_get_proc failed; Could not check capabilities of a current "
            "process. Aborting due to safety reasons.");
        exit(9);
    }

    size_t missing_priviliges_count = 0;

    for (size_t i = 0; i < count; i++) {
        cap_value_t capability_code = required_caps[i];

        cap_flag_value_t flag;
        if (cap_get_flag(capabilities, capability_code, CAP_EFFECTIVE, &flag) !=
            0) {
            perror("cap_get_flag failed");
            cap_free(capabilities);
            panic(
                "Could not check `%s` capability of a current process. "
                "Aborting due to safety reasons.",
                cap_to_name(capability_code));
            exit(10);
        }

        if (flag != CAP_SET) {
            fprintf(stderr, "Missing capability `%s`.\n",
                    cap_to_name(capability_code));
            missing_priviliges_count++;
        }
    }

    if (missing_priviliges_count > 0) {
        char* exe_path = get_executable_path(program_name);

        fprintf(stderr,
                "Missing %zu out of %zu capabilities. Aborting due to safety "
                "reasons.\n\n",
                missing_priviliges_count, count);
        fprintf(stderr,
                "Lack of these priviliges means either invalid/broken "
                "installation, messing around with executable, or malicious "
                "intent.\n");
        fprintf(stderr,
                "If you are the system administrator, you can fix the problem "
                "via:\n`$ sudo setcap cap_sys_admin,cap_sys_ptrace=ep %s`.\n",
                exe_path);

        free(exe_path);
        exit(11);
    }
}

static char* get_executable_path(const char* program_name) {
    char exe_link_path[1024];
    snprintf(exe_link_path, sizeof(exe_link_path), "/proc/%llu/exe",
             (long long unsigned int)getpid());

    char exe_path[8192];
    memset(exe_path, 0, sizeof(exe_path));  // zero out.
    if (readlink(exe_link_path, exe_path, sizeof(exe_path) - 1) < 0) {
        perror(
            "could not get current executable path; falling back to program "
            "name");
        char* string = strdup(program_name);
        if (string == NULL && program_name != NULL)
            panic("Failed to allocate memory");

        return string;
    } else {
        char* string = strdup(exe_path);
        if (string == NULL) panic("Failed to allocate memory");

        return string;
    }
}

static const char* get_setns_errno_description(int errno_number) {
    switch (errno_number) {
        case EBADF:
            return "\tfd is not a valid file descriptor.";
        case EINVAL:
            return "\tfd refers to a namespace whose type does not match that "
                   "specified in nstype; or \n"
                   "\tThere is problem with reassociating the thread with the "
                   "specified namespace; or \n"
                   "\tThe caller tried to join an ancestor (parent, "
                   "grandparent, and so on) PID namespace; or \n"
                   "\tThe caller attempted to join the user namespace in "
                   "which it is already a member; or \n"
                   "\tThe caller shares filesystem (CLONE_FS) state (in "
                   "particular, the root directory) with other processes and "
                   "tried to join a new user namespace; or \n"
                   "\tThe caller is multithreaded and tried to join a new "
                   "user namespace; or \n"
                   "\tfd is a PID file descriptor and nstype is invalid "
                   "(e.g., it is 0).";
        case ENOMEM:
            return "\tCannot allocate sufficient memory to change the "
                   "specified namespace.";
        case EPERM:
            return "\tThe calling thread did not have the required capability "
                   "for this operation.";
        case ESRCH:
            return "\tfd is a PID file descriptor but the process it refers "
                   "to no longer exists (i.e., it has terminated and been "
                   "waited on).";
    }

    return NULL;
}
