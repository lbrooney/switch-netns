# Completions for switch-netns https://github.com/USSURATONCACHI/switch-netns

function __switch_netns_list -d "List named network namespaces (/run/netns/*)"
    set -l files /run/netns/*
    path filter -f -- $files
end

function __switch_netns_complete_pids -d "List PIDs with their netns name (or unassigned)"
    set -l files (__switch_netns_list)
    set -l names (path basename -- $files)
    set -l inodes
    set -q files[1]; and set inodes (stat -Lc %i -- $files)

    # Flat list of pid, netns inode, comm triples (unreadable netns show as "-" and are skipped)
    set -l procs (__fish_ps -o pid=,netns=,comm= | string match -rg '^\s*(\d+)\s+(\d+)\s+(.*)$')
    for i in (seq 1 3 (count $procs))
        set -l name unassigned
        set -l idx (contains -i -- $procs[(math $i + 1)] $inodes); and set name $names[$idx]
        printf '%s\t%s [%s]\n' $procs[$i] $procs[(math $i + 2)] $name
    end
end

function __switch_netns_print_remaining_args -d "Print the command to run (NUL-separated), if one has started after `--`"
    set -l tokens (commandline -xpc | string escape) (commandline -ct)
    set -e tokens[1]
    argparse -s h/help V/version f/by-file= n/by-name= p/by-pid= d/by-fd= -- $tokens 2>/dev/null
    or return
    # What's left is the command and its args, but only if argparse stopped at a `--`
    # (and not at the first non-option, or a `--` given as an option's value)
    set -l sep (math (count $tokens) - (count $argv))
    set -q argv[1]
    and test $sep -gt 0
    and test "$tokens[$sep]" = --
    and string join0 -- $argv
end

function __switch_netns_no_opt_yet -d "Test that no option (and no `--`) has been given yet"
    set -l tokens (commandline -xpc)[2..]
    # When completing an option's value, judge by what came before that option
    set -q tokens[1]
    and contains -- $tokens[-1] -f -n -p -d --by-file --by-name --by-pid --by-fd
    and set -e tokens[-1]
    # The namespace options are a required group that takes exactly one, and -h/-V exit
    # straight away, so every option is mutually exclusive with all the others
    argparse -s h/help V/version f/by-file= n/by-name= p/by-pid= d/by-fd= -- $tokens 2>/dev/null
    and not set -n | string match -q '_flag_*'
    and not contains -- -- $tokens
end

function __switch_netns_complete_subcommand
    set -l args (__switch_netns_print_remaining_args | string split0)

    if not set -q args[1]
        if __switch_netns_no_opt_yet
            # Fish only lists options once the token starts with "-", but a namespace
            # option is required, so offer them on an empty token too (same as "-")
            test -z "$(commandline -ct)"
            and complete -C "$(commandline -pc)-"
        else if argparse -s h/help V/version f/by-file= n/by-name= p/by-pid= d/by-fd= -- (commandline -xpc)[2..] 2>/dev/null
            # A namespace was picked (__fish_seen_argument misses e.g. `-nmy-ns`)
            and set -n | string match -qr '^_flag_[fnpd]$'
            and not contains -- -- (commandline -xpc)
            printf '%s\t%s\n' -- 'Separator before command'
        end
        return
    end

    # Past the command name (or a path to one): defer to that command's own completions.
    # For paths, fish's command-position completion already offers only dirs + executables.
    if set -q args[2]; or string match -q -- '*/*' $args[1]; or string match -q -- '~*' $args[1]
        __fish_complete_subcommand --commandline $args
        return
    end

    # Bare command name: it gets exec'd, so drop functions, builtins and abbreviations
    for line in (__fish_complete_subcommand --commandline $args)
        command -q -- (string split -f1 \t -- $line); and echo $line
    end
end

complete -c switch-netns -n __switch_netns_no_opt_yet -s h -l help -d "Print help and exit"
complete -c switch-netns -n __switch_netns_no_opt_yet -s V -l version -d "Print version and exit"
complete -c switch-netns -n __switch_netns_no_opt_yet -s f -l by-file -d "By filepath (/run/netns/…, /proc/<pid>/ns/net)" -rF -a '(__switch_netns_list)'
complete -c switch-netns -n __switch_netns_no_opt_yet -s n -l by-name -d "By name (/run/netns/<name>, plus /etc/netns/<name>/)" -x -a '(__switch_netns_list | path basename)'
complete -c switch-netns -n __switch_netns_no_opt_yet -s p -l by-pid -d "By PID (same as --by-file /proc/<pid>/ns/net)" -x -a '(__switch_netns_complete_pids)'
complete -c switch-netns -n __switch_netns_no_opt_yet -s d -l by-fd -d "By file descriptor" -x

# The command to run inside the namespace
complete -c switch-netns -x -a '(__switch_netns_complete_subcommand)'
