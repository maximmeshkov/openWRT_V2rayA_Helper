#ifndef V2RAYA_HELPER_FAILOVER_MONITOR_H
#define V2RAYA_HELPER_FAILOVER_MONITOR_H

#include "helper.h"
#include "v2raya_api.h"

struct failover_monitor;
struct latency_history;

struct failover_monitor *failover_monitor_create(const char *path, const struct v2raya_api *api,
    const struct https_options *https, uint32_t mark, struct latency_history *history);
void failover_monitor_free(struct failover_monitor *monitor);
void failover_monitor_reset(struct failover_monitor *monitor);
void failover_monitor_tick(struct failover_monitor *monitor, const struct inventory *inventory,
                           const char *config_path, json_object *config);
int failover_lock_settings(const char *lock_path);
int failover_command(int argc, char **argv);

#endif
