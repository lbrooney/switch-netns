# switch-netns

Simple & secure C utility to change network namespaces without being root.
A wrapper around `setns()` syscall, with permission checks and command line parsing.

Usage:
```sh
$ whoami
ussur
$ switch-netns --by-name my_netns -- whoami
ussur
$ switch-netns --by-name my_netns -- echo 'Hello from other network namespace!'
Hello from other network namespace!
```

You can also specify namespace `--by-file` (for example, `/run/netns/my_netns` or `/proc/1234/ns/net`), and `--by-pid`.

## Build and install

### Via AUR:
```sh
yay -S switch-netns
```

### Manually:

Installation:
```sh
$ make build
$ sudo make install
```

Uninstallation:
```sh
$ sudo make uninstall
```

### Dependencies

- `libcap`,
- `gengetopt` (build dependency),
- a C compiler.
