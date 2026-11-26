#include "core_recovery.h"
#include "failover_api.h"
#include "helper.h"
#include "node_profile.h"
#include <stdio.h>
#include <string.h>

static const struct v2raya_api api = {.base = "http://127.0.0.1:2017"};
static const char config_path[] = "/fixture/config.json";
static int64_t now_ms = 10000;
static unsigned guards, posts;
static unsigned port_prechecks, port_rechecks;
static pid_t owner_pid = 42;
static unsigned long long owner_started = 5;
static int sentinel_port = 20170;
static int core_present = 1, touch_allowed = 1;
static int sentinel_busy, fixed_at_final_check, checking_start;
static int secondary_conflict_at_final, foreign_start_peer;
static volatile sig_atomic_t stopping;

int64_t probe_clock_ms(void) { return now_ms; }

json_object *node_config_read(const char *path)
{
    if (strcmp(path, config_path)) return NULL;
    json_object *config = json_object_new_object();
    json_object_object_add(config, "port", json_object_new_int(sentinel_port));
    return config;
}

enum core_watch_state core_watch_sample(const char *base, const char *path,
                                        json_object *config, struct core_watch_sample *sample)
{
    if (strcmp(base, api.base) || strcmp(path, config_path) || !config) return CORE_WATCH_UNKNOWN;
    *sample = (struct core_watch_sample){.owner = owner_pid, .owner_started = owner_started,
                                         .core = core_present ? 43 : 0, .port = sentinel_port};
    if (core_present) return CORE_WATCH_HEALTHY;
    return sentinel_busy ? CORE_WATCH_API_PORT_BUSY : CORE_WATCH_MISSING;
}

int core_watch_owner_childless(const struct core_watch_sample *sample)
{
    return sample->owner == owner_pid && sample->owner_started == owner_started &&
           sample->port == sentinel_port && !core_present;
}

int core_watch_still_absent(const struct core_watch_sample *sample)
{
    return !sentinel_busy && core_watch_owner_childless(sample);
}

int core_watch_start_conflicts(json_object *config, const struct core_watch_sample *sample)
{
    if (!config || !core_watch_owner_childless(sample)) return -1;
    if (checking_start && secondary_conflict_at_final) return CORE_PORT_FIXED_LOCAL;
    return sentinel_busy ? CORE_PORT_API_LOCAL | CORE_PORT_API_TCP4 : 0;
}

int core_watch_verify_peer(void *context, char *remote_ip, char *local_ip, int remote_port, int local_port)
{
    const struct core_watch_peer *peer = context;
    return !(peer && peer->expected && peer->api && peer->stopping == &stopping && !stopping &&
             !strcmp(peer->api, api.base) && core_watch_owner_childless(peer->expected) &&
             !strcmp(remote_ip, "127.0.0.1") && !strcmp(local_ip, "127.0.0.1") &&
             remote_port == 2017 && local_port == 45000);
}

int v2raya_api_core_port_automatic(const struct v2raya_api *client, v2raya_login_peer peer, void *context,
                                   char *error, size_t len)
{
    char loopback[] = "127.0.0.1";
    if (client != &api || !peer || peer(context, loopback, loopback, 2017, 45000)) {
        snprintf(error, len, "the test request did not verify the expected v2rayA owner");
        return 0;
    }
    if (checking_start) {
        ++port_rechecks;
        return !fixed_at_final_check;
    }
    ++port_prechecks;
    return 1;
}

int v2raya_api_port_sharing(const struct v2raya_api *client, v2raya_login_peer peer, void *context,
                            char *error, size_t len)
{
    (void)client;
    (void)peer;
    (void)context;
    (void)error;
    (void)len;
    return -1;
}

int failover_api_can_switch(const struct v2raya_api *client, char *error, size_t len)
{
    (void)error;
    (void)len;
    return client == &api;
}

json_object *v2raya_api_touch_data(const struct v2raya_api *client, char *error, size_t len)
{
    if (client != &api || !touch_allowed) {
        snprintf(error, len, "the last request is being processed");
        return NULL;
    }
    json_object *touch = json_object_new_object();
    json_object_object_add(touch, "running", json_object_new_boolean(1));
    return touch;
}

int v2raya_api_start_core(const struct v2raya_api *client, v2raya_login_peer permitted, void *context,
                         char *error, size_t len)
{
    if (client != &api) return -1;
    ++guards;
    checking_start = 1;
    char loopback[] = "127.0.0.1";
    int allowed = !permitted(context, loopback, loopback, foreign_start_peer ? 2018 : 2017, 45000);
    checking_start = 0;
    if (allowed) {
        ++posts;
        snprintf(error, len, "timed out waiting for the response to POST");
    }
    return -1;
}

static void tick(struct core_recovery *state, int64_t elapsed_ms)
{
    now_ms += elapsed_ms;
    core_recovery_tick(state, &api, config_path, 1, &stopping);
}

static int require(int condition, const char *message)
{
    if (!condition) fprintf(stderr, "%s\n", message);
    return condition;
}

static int verify_port_rotation(struct core_recovery *state)
{
    for (unsigned port_number = 2; port_number <= 4; ++port_number) {
        ++sentinel_port;
        tick(state, 60001);
        tick(state, 1001);
        unsigned expected = port_number < 3 ? port_number : 3;
        if (!require(posts == expected && guards == expected,
                     "the same v2rayA owner lost its three-attempt limit when the sentinel changed"))
            return 1;
    }
    /* Even a reused PID must earn a fresh budget when its start time changes. */
    ++owner_started;
    ++sentinel_port;
    tick(state, 60001);
    tick(state, 1001);
    return require(posts == 4 && guards == 4, "a new v2rayA process did not get a fresh budget") ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    int veto = !strcmp(argv[1], "veto");
    int rotate_port = !strcmp(argv[1], "rotate-port");
    int busy_port_veto = !strcmp(argv[1], "busy-port-veto");
    int secondary_port_veto = !strcmp(argv[1], "secondary-port-veto");
    int foreign_peer_veto = !strcmp(argv[1], "foreign-peer-veto");
    int vetoed = veto || busy_port_veto || secondary_port_veto || foreign_peer_veto;
    if (!rotate_port && !vetoed && strcmp(argv[1], "uncertain")) return 2;
    struct core_recovery state = {0};
    core_recovery_init(&state, argv[2], api.base, config_path);
    if (!require(state.checkpoint != NULL, "could not open the real recovery checkpoint")) return 1;

    if (!rotate_port) tick(&state, 0);
    core_present = 0;
    touch_allowed = !veto;
    sentinel_busy = fixed_at_final_check = busy_port_veto;
    secondary_conflict_at_final = secondary_port_veto;
    foreign_start_peer = foreign_peer_veto;
    tick(&state, 1001);
    tick(&state, 1001);
    if (!require(guards == 1 && posts == !vetoed,
                 "unexpected initial recovery dispatch")) return 1;
    if (busy_port_veto && !require(port_prechecks > 0 && port_rechecks == 1,
                                  "occupied API port did not exercise both verified settings reads")) return 1;
    if (rotate_port) {
        int result = verify_port_rotation(&state);
        core_recovery_close(&state);
        return result;
    }
    int64_t attempted_at = now_ms;

    core_recovery_close(&state);
    state = (struct core_recovery){0};
    core_recovery_init(&state, argv[2], api.base, config_path);
    if (!require(state.checkpoint != NULL, "could not reopen the real recovery checkpoint")) return 1;
    touch_allowed = 1;
    fixed_at_final_check = 0;
    secondary_conflict_at_final = 0;
    foreign_start_peer = 0;
    tick(&state, 1001);
    tick(&state, 1001);
    if (vetoed) {
        if (!require(guards == 2 && posts == 1,
                     "the preflight veto prevented a fresh attempt before 60 seconds")) return 1;
        if (busy_port_veto && !require(port_rechecks == 2, "the replacement check did not verify the port again"))
            return 1;
    } else {
        if (!require(guards == 1 && posts == 1, "an uncertain POST lost its cooldown after restart")) return 1;
        tick(&state, attempted_at + 59999 - now_ms);
        if (!require(posts == 1, "an uncertain POST retried before 60 seconds")) return 1;
        tick(&state, 2);
        if (!require(posts == 2, "recovery did not retry after the uncertain POST's cooldown")) return 1;
    }
    core_recovery_close(&state);
    return 0;
}
