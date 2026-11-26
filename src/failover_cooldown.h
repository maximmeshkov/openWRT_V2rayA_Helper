#ifndef V2RAYA_HELPER_FAILOVER_COOLDOWN_H
#define V2RAYA_HELPER_FAILOVER_COOLDOWN_H

#include <time.h>
#include "failover_policy.h"

enum {
    FAILOVER_COOLDOWN_BLOCKED = -1,
    FAILOVER_COOLDOWN_LEGACY_FUTURE = -2,
    FAILOVER_COOLDOWN_EXPIRED = FAILOVER_MAX_COOLDOWN + 1
};

/* Elapsed seconds after the previous attempt, or a negative value while blocked. */
long failover_cooldown_age(const char *path, const char *boot_id, time_t now);
/* Run under the settings lock. Only converts uncertain legacy state or removes an expired v2 record. */
void failover_cooldown_maintain(const char *path, const char *boot_id, time_t now);
int failover_cooldown_save(const char *path, const char *boot_id, time_t now, unsigned duration);

#endif
