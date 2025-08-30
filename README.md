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

### Per-namespace `/etc` files

Like `ip netns exec`, `--by-name my_netns` bind-mounts every file in `/etc/netns/my_netns/` over the matching file in `/etc`, visible only to the command.
Use this to keep DNS inside the namespace:

- `/etc/netns/my_netns/resolv.conf` with the namespace's nameserver;
- `/etc/netns/my_netns/nsswitch.conf` with `resolve` (and `mdns*`) removed from the `hosts:` line.
  With `systemd-resolved`, `nss-resolve` sends lookups over a Unix socket to the host's resolver, bypassing the namespace.

`/etc/netns` and `/etc/netns/my_netns` must be owned by root and not writable by group or others.
If the files can't be applied, the command is not run.

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
