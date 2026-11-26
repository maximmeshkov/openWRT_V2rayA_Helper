#ifndef V2RAYA_HELPER_FAILOVER_POLICY_H
#define V2RAYA_HELPER_FAILOVER_POLICY_H

#include <json-c/json.h>
#include <stddef.h>
#include <time.h>

#define FAILOVER_ID_LIMIT 96
#define FAILOVER_DEFAULT_FAILURES 3
#define FAILOVER_DEFAULT_COOLDOWN 900

enum failover_mode { FAILOVER_OFF, FAILOVER_OUTAGE, FAILOVER_SCHEDULED };
enum failover_probe_state { FAILOVER_UNKNOWN, FAILOVER_OK, FAILOVER_FAILED };

/* Names and candidate IDs borrow storage from the settings object. */
struct failover_policy {
    enum failover_mode mode;
    unsigned failures, max_ms, cooldown_seconds, start_minute, end_minute;
    const char *outbound;
    json_object *candidates;
};

struct failover_sample {
    const char *id;
    enum failover_probe_state state;
    long ms;
    time_t checked;
};

struct failover_streak {
    char id[FAILOVER_ID_LIMIT + 1];
    time_t checked;
    unsigned failed, slow;
};

/* Entry shape: {outbound, mode, candidates, failures?, max_ms?,
 * cooldown_seconds?, start?, end?}. Settings shape: {policies:[entries]}.
 * A missing file means no policies. Malformed or unreadable files return NULL. */
int failover_policy_parse(json_object *entry, struct failover_policy *policy);
json_object *failover_settings_read(const char *path);
int failover_settings_write(const char *path, json_object *settings);

/* A failed sample is a confirmed probe failure. Unsupported or unavailable
 * means UNKNOWN and clears the run. active id must change with its profile. */
void failover_record(struct failover_streak *streak, const struct failover_policy *policy,
                     const struct failover_sample *active, time_t now, long maximum_age);

/* Check whether it is time to probe candidates. */
int failover_policy_ready(const struct failover_policy *policy,
                const struct failover_sample *active, const struct failover_streak *streak,
                time_t now, long maximum_age, time_t last_switch);

/* Return a borrowed ID from samples or NULL. last_switch is the latest
 * attempted switch timestamp, including attempts for a different outbound.
 * A candidate must succeed at or after the newest active-node sample. */
const char *failover_policy_choose(const struct failover_policy *policy,
                const struct failover_sample *active, const struct failover_streak *streak,
                const struct failover_sample *samples, size_t count, time_t now,
                long maximum_age, time_t last_switch);

#endif
