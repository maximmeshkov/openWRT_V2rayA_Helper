#ifndef V2RAYA_HELPER_FAILOVER_POLICY_H
#define V2RAYA_HELPER_FAILOVER_POLICY_H

#include <json-c/json.h>
#include <stddef.h>
#include <time.h>

#define FAILOVER_ID_LIMIT 96
#define FAILOVER_SELECTION_LIMIT 64
#define FAILOVER_DEFAULT_FAILURES 3
#define FAILOVER_MAX_FAILURES 30
#define FAILOVER_DEFAULT_WINDOW_MINUTES 10
#define FAILOVER_DEFAULT_COOLDOWN 900

enum failover_mode { FAILOVER_OFF, FAILOVER_OUTAGE, FAILOVER_SCHEDULED };
enum failover_failure_method { FAILOVER_CONSECUTIVE, FAILOVER_WINDOW };
enum failover_probe_state { FAILOVER_UNKNOWN, FAILOVER_OK, FAILOVER_FAILED };

/* Names and selection keys borrow storage from the settings object. */
struct failover_policy {
    enum failover_mode mode;
    unsigned failures, max_ms, cooldown_seconds, start_minute, end_minute;
    const char *outbound;
    json_object *candidates;
    enum failover_failure_method failure_method;
    unsigned failure_window_minutes;
    json_object *subscriptions;
};

struct failover_sample {
    const char *id;
    enum failover_probe_state state;
    long ms;
    time_t checked;
    const char *subscription;
};

struct failover_streak {
    char id[FAILOVER_ID_LIMIT + 1];
    time_t checked;
    unsigned failed, slow;
    enum failover_probe_state latest;
    unsigned window_count;
    time_t failure_times[FAILOVER_MAX_FAILURES];
};

/* Entry shape: {outbound, mode, candidates, subscriptions?, failures?, max_ms?,
 * cooldown_seconds?, start?, end?, failure_method?, failure_window_minutes?}.
 * Settings shape: {policies:[entries]}.
 * A missing file means no policies. Malformed or unreadable files return NULL. */
int failover_policy_parse(json_object *entry, struct failover_policy *policy);
json_object *failover_settings_read(const char *path);
int failover_settings_write(const char *path, json_object *settings);

/* Check an explicit node key or a uniquely resolved subscription's key. */
int failover_policy_selects(const struct failover_policy *policy, const char *id, const char *subscription);

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
