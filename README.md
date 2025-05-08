# switch-netns

Simple & secure C utility to change network namespaces without being root.

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
(TODO)

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
