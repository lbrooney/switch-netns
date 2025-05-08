#include <linux/prctl.h>
#include <prettify/panic.h>
#include <stdint.h>
#include <stdio.h>
#include <switch-netns/capabilities.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

CapabilitySets CapabilitySets_by_pid(pid_t pid) {
	char path[2048];
	snprintf(path, sizeof(path), "/proc/%d/status", pid);

	FILE* f = fopen(path, "r");
	if (!f) panic("fopen failed: %s - could not check capabilities", path);

	CapabilitySets caps = {0, 0, 0, 0, 0};
	char line[256];

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "CapInh: %lx", &caps.inh) == 1) continue;
		if (sscanf(line, "CapPrm: %lx", &caps.prm) == 1) continue;
		if (sscanf(line, "CapEff: %lx", &caps.eff) == 1) continue;
		if (sscanf(line, "CapBnd: %lx", &caps.bnd) == 1) continue;
		if (sscanf(line, "CapAmb: %lx", &caps.amb) == 1) continue;
	}

	fclose(f);
	return caps;
}

void CapabilitySets_apply(CapabilitySets sets) {
	panic("Not yet implemented!")
}
