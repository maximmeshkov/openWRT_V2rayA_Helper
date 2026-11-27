#ifndef V2RAYA_HELPER_PROBE_CORE_H
#define V2RAYA_HELPER_PROBE_CORE_H

#include "core_kind.h"
#include <json-c/json.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* A separate core process carries the HTTPS checks through servers whose
 * protocol only the core speaks. It never touches the core v2rayA runs: it is
 * the helper's own child, reads its own config from stdin and listens only on
 * 127.0.0.1, one SOCKS inbound per server. */

/* Build the probe config: inbound i on 127.0.0.1:ports[i] leads to a copy of
 * outbounds[i]. An outbound without a socket mark gets `mark`. No IO. */
json_object *probe_core_config(json_object *const *outbounds, const int *ports, size_t count, uint32_t mark);
/* Pick distinct free loopback TCP ports. Returns 0 on success. */
int probe_core_ports(int *ports, size_t count);
/* Start the core with the config on stdin. Returns its PID once every port
 * accepts connections, or -1 when it exits or startup_ms passes first. */
pid_t probe_core_start(const struct core_kind *kind, const char *binary, json_object *config,
                       const int *ports, size_t count, int startup_ms);
void probe_core_stop(pid_t core);
void probe_core_reap(void);

#endif
