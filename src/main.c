#define _GNU_SOURCE
#include <cmdline.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <prettify/misc.h>
#include <prettify/panic.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "prettify/assert.h"

#define PRODUCT_NAME "switch-netns"

typedef int8_t Maybe;
#define MAYBE_UNKNOWN 0
#define MAYBE_FALSE 1
#define MAYBE_TRUE 2

// Print
typedef struct {
    int namespace_fd;
    int argc;
    char* const* argv;
    char* netns_name;
} LaunchParams;
static LaunchParams parse_launch_params(const char* program_name, int argc, char** argv);

static Maybe get_effective_capability(cap_value_t capability);

// Just general utility functions.
static void check_capability(const char* program_name);
static char* get_executable_path(const char* program_name);
static void show_usage(const char* program_name);
static const char* get_setns_errno_description(int errno_number);
static bool string_starts_with(const char* string, const char* starts_with);
static void show_setcap_fix_suggestion(const char* program_name);
static void bind_one(const char* src, const char* dst);
static int mount_resolv_and_nsswitch_if_exists(const char* netns_name);

int main(int argc, char** argv) {
    const char* program_name = argv[0];

    if (argc == 1) { // No CLI arguments
        show_usage(program_name);
        exit(1);
    }

    // Make user know if we miss hard-needed capability/capabilities.
    // `cap_sys_admin` - to do `setns()` call
    // `cap_sys_ptrace` - for procfs access of some PIDs. But this one is optional, not hard-needed.
    check_capability(program_name);

    // Parse cmdline.
    LaunchParams params = parse_launch_params(program_name, argc, argv);
    if (params.argc == 0) {
        fprintf(stderr, "No command provided.\n\n");
        show_usage(program_name);
        exit(2);
    }

    // Switch network namespace.
    if (setns(params.namespace_fd, CLONE_NEWNET) != 0) {
        const char* setns_error_description = get_setns_errno_description(errno);
        perror("failed to set network namespace");

        if (setns_error_description)
            fprintf(stderr, "%s\n", setns_error_description);

        exit(3);
    }

    if (params.netns_name != NULL) {
        int mrc = mount_resolv_and_nsswitch_if_exists(params.netns_name);
        free(params.netns_name);
        if (mrc != 0) {
            fprintf(stderr,
                    "failed to establish private mount namespace for "
                    "per-namespace /etc; aborting\n");
            exit(4);
        }
    }

    // File is opened with O_CLOEXEC, so it will be closed automatically.

    // Execute user-provided command.
    execvp(params.argv[0], params.argv);

    // Handle error
    perror("execvpe failed");
    fprintf(stderr, "could not execute user program '%s'\n", params.argv[0]);
    exit(5);
}

static void show_usage(const char* program_name) {
    fprintf(stderr, "Usage: %s --by-name my_ns -- <command> <args...>\n", program_name);
    fprintf(stderr, "       %s --by-file /run/netns/my_ns -- <command> <args...>\n", program_name);
    fprintf(stderr, "       %s --by-pid 1234 -- <command> <args...>\n", program_name);
    fprintf(stderr, "       %s --by-fd 3 -- <command> <args...>\n", program_name);
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

    LaunchParams result = (LaunchParams){
        .namespace_fd = -1,
        .argc = argc - dash_position - 1,
        .argv = &argv[dash_position + 1],
        .netns_name = NULL,
    };
    char* filepath = NULL;

    if (args_info.by_file_given) {
        filepath = strdup(args_info.by_file_arg);
        assert_alloc(filepath);
    } else if (args_info.by_name_given) {
        // ==== BY NAME ====
        const char* netns_name = args_info.by_name_arg;
        result.netns_name = strdup(netns_name);
        assert_alloc(result.netns_name);

        size_t needed_len = strlen("/run/netns/%s") + strlen(netns_name) + 1;
        filepath = (char*)calloc(needed_len, sizeof(char));
        assert_alloc(filepath);
        snprintf(filepath, needed_len - 1, "/run/netns/%s", netns_name);
    } else if (args_info.by_pid_given) {
        long pid = args_info.by_pid_arg;

        char buffer[2048] = "\0";
        snprintf(buffer, LEN(buffer) - 1, "/proc/%ld/ns/net", pid);

        filepath = strdup(buffer);
        assert_alloc(filepath);
    } else if (args_info.by_fd_given) {
        result.namespace_fd = args_info.by_fd_arg;
        return result;
    } else {
        fprintf(stderr, "No network namespace resolution way (`--by-name`, `--by-file`, `--by-pid`, or `--by-fd`) provided.");
        show_usage(program_name);
        exit(7);
    }

    if (filepath == NULL)
        panic(
            "Internal error: Failed to establish filepath of network "
            "namespace.");

    // We do not want to pass that file descriptor to any child to avoid permission issues:
    //      It could have been opened via `setcap`-ped `cap_sys_ptrace`, and the child may not have it.
    result.namespace_fd = open(filepath, O_RDONLY | O_CLOEXEC);
    if (result.namespace_fd < 0) {
        perror("open failed; could not open namespace file");
        fprintf(stderr, "Could not open namespace file '%s'.\n\n", filepath);

        if (string_starts_with(filepath, "/proc/")) {
            Maybe has_ptrace = get_effective_capability(CAP_SYS_PTRACE);
            if (has_ptrace == MAYBE_FALSE) {
                fprintf(stderr, "Current process lacks `cap_sys_ptrace` capability.\n");
                fprintf(stderr, "It may be required to access _some_ of the `/proc/` entries.\n\n");

                show_setcap_fix_suggestion(program_name);
            } else if (has_ptrace == MAYBE_UNKNOWN) {
                fprintf(stderr, "Current process might lack `cap_sys_ptrace` capability.\n");
                fprintf(stderr, "It may be required to access some of the `/proc/` entries.\n");
            }
        }
        free(filepath);
        exit(8);
    }
    free(filepath);

    return result;
}

static void check_capability(const char* program_name) {
    const cap_value_t required_cap = CAP_SYS_ADMIN;

    cap_t capabilities = cap_get_proc();
    if (!capabilities) {
        perror("cap_get_proc failed; Could not check capabilities of a current process.");
        return; // We do not need to exit. We will just fail on the operation that requires the capability.
    }

    cap_flag_value_t flag;
    if (cap_get_flag(capabilities, required_cap, CAP_EFFECTIVE, &flag) != 0) {
        perror("cap_get_flag failed");
        fprintf(stderr, "Could not check `%s` capability of a runnning process. The operation may fail.", cap_to_name(required_cap));
    } else if (flag != CAP_SET) {
        fprintf(stderr, "Missing capability `%s`. The operation will fail.\n\n", cap_to_name(required_cap));
        show_setcap_fix_suggestion(program_name);
    }
    cap_free(capabilities);
}

static Maybe get_effective_capability(cap_value_t required_cap) {
    cap_t capabilities = cap_get_proc();
    if (!capabilities)
        return MAYBE_UNKNOWN;

    cap_flag_value_t flag;
    if (cap_get_flag(capabilities, required_cap, CAP_EFFECTIVE, &flag) != 0)
        return MAYBE_UNKNOWN;

    return flag == CAP_SET ? MAYBE_TRUE : MAYBE_FALSE;
}


static char* get_executable_path(const char* program_name) {
    char exe_link_path[1024];
    snprintf(exe_link_path, sizeof(exe_link_path), "/proc/%llu/exe",
             (long long unsigned int)getpid());

    char exe_path[8192];
    memset(exe_path, 0, sizeof(exe_path));  // zero out.
    if (readlink(exe_link_path, exe_path, sizeof(exe_path) - 1) < 0) {
        perror("could not get current executable path; falling back to program name");
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

// See `$ man 2 setns`, part `ERRORS` for more info.
static const char* get_setns_errno_description(int errno_number) {
    switch (errno_number) {
        case EBADF:
            return "[EBADF] Provided file descriptor is invalid.";
        case EINVAL:
            return "[EINVAL] One of the following problems occured:\n"
                   "\t- File (provided via `--by-file`) refers to a non-network namespace;\n"
                   "\t- There is a problem with reassociating the thread with the specified namespace;\n"
                   "\t- File descritor is a PID file descriptor and namespace type is invalid.";
        case ENOMEM:
            return "[ENOMEM] Cannot allocate sufficient memory to change the specified namespace.";
        case EPERM:
            return "[EPERM] Current process does not have the required capability (`cap_sys_admin`) for this operation.";
        case ESRCH:
            return "[ESRCH] Namespace file's descriptor is a PID file descriptor but the process it refers "
                   "to no longer exists (i.e., it has terminated and been waited on).";
    }

    return NULL;
}

static bool string_starts_with(const char* string, const char* starts_with) {
    return strncmp(string, starts_with, strlen(starts_with)) == 0;
}

static void show_setcap_fix_suggestion(const char* program_name) {
    char* exe_path = get_executable_path(program_name);

    fprintf(stderr, "Note that `" PRODUCT_NAME "` by default comes with capabilities pre-set. ");
    fprintf(stderr, "Lack of privilige(s) means either invalid/broken/custom installation, messing around with executable, or malicious intent. ");
    fprintf(stderr, "If you are the system administrator, you can fix the problem via:\n`$ sudo setcap cap_sys_admin,cap_sys_ptrace=ep %s`.\n",exe_path);
    fprintf(stderr, "- `cap_sys_admin`  - is required to change a namespace.\n");
    fprintf(stderr, "- `cap_sys_ptrace` - optional, only required for accessing namespaces `--by-pid` or via procfs.\n\n");

    fprintf(stderr, "Alternatively, just run the program as root (via `sudo`) to gain privileges directly.\n\n");

    free(exe_path);
}

static int mount_resolv_and_nsswitch_if_exists(const char* netns_name) {
    char src_resolv[PATH_MAX];
    char src_nsswitch[PATH_MAX];

    int rc1 = snprintf(src_resolv, sizeof(src_resolv),
                       "/etc/netns/%s/resolv.conf", netns_name);
    int rc2 = snprintf(src_nsswitch, sizeof(src_nsswitch),
                       "/etc/netns/%s/nsswitch.conf", netns_name);
    if (!(rc1 > 0 && (size_t)rc1 < sizeof(src_resolv))) {
        fprintf(stderr,
                "warning: namespace name too long, skipping "
                "resolv.conf/nsswitch\n");
        return 0;
    }

    /* Check which files exist and are regular files */
    struct stat st_resolv, st_nsswitch;
    bool have_resolv =
        (stat(src_resolv, &st_resolv) == 0 && S_ISREG(st_resolv.st_mode));
    bool have_nsswitch =
        (rc2 > 0 && (size_t)rc2 < sizeof(src_nsswitch) &&
         stat(src_nsswitch, &st_nsswitch) == 0 && S_ISREG(st_nsswitch.st_mode));

    if (!have_resolv && !have_nsswitch) {
        return 0;
    }

    if (unshare(CLONE_NEWNS) != 0) {
        fprintf(stderr, "error: unshare(CLONE_NEWNS) failed: %s\n",
                strerror(errno));
        return -1;
    }

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        fprintf(stderr, "warning: failed to make mounts private: %s\n",
                strerror(errno));
        return 0;
    }

    if (have_resolv) {
        bind_one(src_resolv, "/etc/resolv.conf");
    }

    if (have_nsswitch) {
        bind_one(src_nsswitch, "/etc/nsswitch.conf");
    }

    return 0;
}

static void bind_one(const char* src, const char* dst) {
    if (mount(src, dst, NULL, MS_BIND, NULL) != 0) {
        fprintf(stderr, "warning: bind mount %s -> %s failed: %s\n", src, dst,
                strerror(errno));
    }
}
