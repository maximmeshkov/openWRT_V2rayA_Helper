#ifndef V2RAYA_HELPER_LATENCY_HISTORY_H
#define V2RAYA_HELPER_LATENCY_HISTORY_H

#include "helper.h"

struct latency_history;

/* The private snapshot is restored if it exists. The caller supplies a path
 * in the helper's runtime directory on tmpfs. */
struct latency_history *latency_history_create(const char *path);
void latency_history_free(struct latency_history *history);

/* Only completed, attributable HTTPS samples enter the history. Strings are
 * copied. The role is "active" or "reserve"; the series is an opaque ID. */
void latency_history_add(struct latency_history *history, const char *outbound,
                         const char *server, const char *series,
                         const struct measurement *sample, const char *role);
int latency_history_publish(struct latency_history *history, time_t now);

/* Emit the available outbound names and one optional series of samples. */
int latency_history_rpc(const char *path, const char *outbound);

#endif
