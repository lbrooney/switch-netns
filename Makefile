HEADERS=$(wildcard include/**/*.h)
SOURCES=$(wildcard src/*.c)

run: build
	./build-dir/switch-netns

.PHONY: build setcaps
build: build-dir/switch-netns setcaps

setcaps: build-dir/switch-netns
	sudo setcap cap_sys_admin,cap_sys_ptrace=ep ./build-dir/switch-netns

build-dir/switch-netns: build-dir $(SOURCES) $(HEADERS) build-dir/tmp/include/cmdline.h Makefile
	cc -I./include -I./build-dir/tmp/include -o build-dir/switch-netns ${SOURCES}  build-dir/tmp/include/cmdline.c -lcap

build-dir/tmp/include/cmdline.h: build-dir/tmp/include cmdline.ggo
	gengetopt --input=cmdline.ggo --file-name=cmdline
	mv cmdline.h build-dir/tmp/include/
	mv cmdline.c build-dir/tmp/include/

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
