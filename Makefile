HEADERS=$(wildcard include/**/*.h)
SOURCES=$(wildcard src/*.c)

all: build setcaps

.PHONY: build setcaps
build: build-dir/switch-netns

setcaps: build-dir/switch-netns
	echo "Changing setcaps might require sudo. You can use \`\$ sudo make setcaps\` to only do that with sudo."
	setcap cap_sys_admin,cap_sys_ptrace=ep ./build-dir/switch-netns

build-dir/switch-netns: build-dir $(SOURCES) $(HEADERS) build-dir/tmp/include/cmdline.h Makefile
	cc -I./include -I./build-dir/tmp/include -o build-dir/switch-netns ${SOURCES}  build-dir/tmp/include/cmdline.c -lcap

build-dir/tmp/include/cmdline.h: build-dir/tmp/include cmdline.ggo
	gengetopt --input=cmdline.ggo --file-name=cmdline
	mv cmdline.h build-dir/tmp/include/
	mv cmdline.c build-dir/tmp/include/

install: build-dir/switch-netns
	echo "Installing."
	install -Dm755 build-dir/switch-netns /usr/bin/switch-netns
	setcap cap_sys_admin,cap_sys_ptrace=ep /usr/bin/switch-netns

uninstall:
	echo "Uninstalling."
	rm -rf /usr/bin/switch-netns

# Directories

build-dir/tmp/include:
	mkdir -p $@
build-dir/tmp:
	mkdir -p $@
build-dir:
	mkdir -p $@

# Other

clean:
	rm -rf build-dir

.PHONY: compile_commands.json
compile_commands.json:
	bear -- make
