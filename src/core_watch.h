#ifndef V2RAYA_HELPER_CORE_WATCH_H
#define V2RAYA_HELPER_CORE_WATCH_H

#include <json-c/json.h>
#include <signal.h>
#include <sys/types.h>

struct core_watch_sample {
    pid_t owner;
    unsigned long long owner_started;
    pid_t core;
    unsigned long long core_started;
    int port;
};

enum core_watch_state {
    CORE_WATCH_UNKNOWN, CORE_WATCH_HEALTHY, CORE_WATCH_MISSING, CORE_WATCH_PORT_BUSY, CORE_WATCH_API_PORT_BUSY
};

enum core_watch_conflict {
    CORE_PORT_FIXED_LOCAL = 1, CORE_PORT_FIXED_OTHER = 2,
    CORE_PORT_API_LOCAL = 4, CORE_PORT_API_OTHER = 8, CORE_PORT_API_TCP4 = 16
};

/* Recognize a numeric HTTP endpoint. Its local assignment is checked when dialing. */
int core_watch_local_api(const char *api);

enum core_watch_state core_watch_sample(const char *api, const char *config_path,
                                        json_object *config, struct core_watch_sample *sample);
/* Reconfirm an already verified missing-core sample immediately before starting it. */
int core_watch_still_absent(const struct core_watch_sample *sample);
/* Require a verified local v2rayA owner and no live child under any config or name. */
int core_watch_owner_childless(const struct core_watch_sample *sample);
/* Read the local socket tables for generated Xray inbounds before a start. */
int core_watch_start_conflicts(json_object *config, const struct core_watch_sample *sample);
/* Return the stock wildcard REDIRECT listener under the sampled owner, or zero. */
unsigned long long core_watch_redirect_listener(const struct core_watch_sample *sample);

struct core_watch_peer {
    const char *api;
    const volatile sig_atomic_t *stopping;
    const struct core_watch_sample *expected;
};

/* Verify the accepting v2rayA process before curl sends the request. */
int core_watch_verify_peer(void *context, char *remote_ip, char *local_ip, int remote_port, int local_port);

#endif
