#ifndef SWITCH_NETNS_CAPABILITIES_H_
#define SWITCH_NETNS_CAPABILITIES_H_

#include <stdint.h>
#include <sys/types.h>

typedef struct {
	uint64_t inh;
	uint64_t prm;
	uint64_t eff;
	uint64_t bnd;
	uint64_t amb;
} CapabilitySets;

CapabilitySets CapabilitySets_by_pid(pid_t pid);
void CapabilitySets_apply(CapabilitySets sets);

#endif // SWITCH_NETNS_CAPABILITIES_H_
