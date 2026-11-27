#include "core_recovery.h"
#include "capability.h"
#include "helper.h"
#include "node_profile.h"
#include "recovery_checkpoint.h"
#include <stdio.h>

static const int64_t confirmation_ms = 1000;
static const int64_t recovery_pause_ms = 60000;

static int same_owner(const struct core_watch_sample *a, const struct core_watch_sample *b)
{
    return a->owner == b->owner && a->owner_started == b->owner_started;
}

static int same_instance(const struct core_watch_sample *a, const struct core_watch_sample *b)
{
    return same_owner(a, b) && a->port == b->port;
}

static int confirm_witness(struct core_recovery *state, const struct core_watch_sample *missing, int busy)
{
    int same = same_instance(&state->witness, missing);
    if (same && state->witness.core && !busy) return 1;
    /* Authenticated running=true in 2.2.7.4 describes a core v2rayA already
     * started. Without our own healthy sample, exclude any surviving child. */
    if (!core_watch_owner_childless(missing)) return 0;
    if (!same) {
        if (!same_owner(&state->witness, missing)) state->attempts = 0;
        state->witness = *missing;
        state->missing_since = 0;
    }
    return 1;
}

void core_recovery_init(struct core_recovery *state, const char *path, const char *api, const char *config_path)
{
    if (!path) return;
    state->checkpoint_required = 1;
    state->checkpoint = recovery_checkpoint_open(path, api, config_path, state);
    if (!state->checkpoint)
        fputs("v2raya-helper: Xray recovery disabled because its state file is unavailable\n", stderr);
}

void core_recovery_close(struct core_recovery *state)
{
    recovery_checkpoint_close(state->checkpoint);
}

static void refresh_checkpoint(struct core_recovery *state)
{
    if (!state->checkpoint) return;
    int saved = recovery_checkpoint_save(state->checkpoint, state);
    if (!saved && !state->checkpoint_dirty)
        fputs("v2raya-helper: could not save Xray recovery state\n", stderr);
    state->checkpoint_dirty = !saved;
}

struct start_guard {
    struct core_recovery *recovery;
    const struct v2raya_api *api;
    const char *path;
    json_object *config;
    const volatile sig_atomic_t *stopping;
    int state_error, request_allowed;
    const char *port_error;
};

static const char *unavailable_ports(const struct v2raya_api *api, json_object *config,
                                    const struct core_watch_sample *owner, const volatile sig_atomic_t *stopping)
{
    int conflicts = core_watch_start_conflicts(config, owner);
    if (conflicts < 0 || *stopping) return "Xray inbound ports could not be verified";
    if (conflicts & CORE_PORT_FIXED_LOCAL) return "An Xray inbound port is occupied";

    struct core_watch_peer peer = {.api = api->base, .stopping = stopping, .expected = owner};
    char error[160] = {0};
    if (conflicts & (CORE_PORT_FIXED_OTHER | CORE_PORT_API_OTHER)) {
        int sharing = v2raya_api_port_sharing(api, core_watch_verify_peer, &peer, error, sizeof(error));
        if (sharing < 0) return "Xray inbound port sharing could not be verified";
        if (sharing && (conflicts & CORE_PORT_FIXED_OTHER)) return "An Xray inbound port is occupied";
        if (!sharing) conflicts &= ~CORE_PORT_API_OTHER;
    }
    if (!(conflicts & (CORE_PORT_API_LOCAL | CORE_PORT_API_OTHER))) return NULL;
    /* A live IPv4 TCP holder prevents v2rayA's tcp4 allocator from selecting this number again. */
    if ((conflicts & CORE_PORT_API_TCP4) &&
        v2raya_api_core_port_automatic(api, core_watch_verify_peer, &peer, error, sizeof(error))) return NULL;
    return "Xray API port is occupied";
}

static enum core_watch_state observe_unchanged(const struct start_guard *guard, struct core_watch_sample *sample)
{
    json_object *current = node_config_read(guard->path);
    enum core_watch_state result = CORE_WATCH_UNKNOWN;
    if (current && json_object_equal(guard->config, current))
        result = core_watch_sample(guard->api->base, guard->path, current, sample);
    json_object_put(current);
    return same_instance(&guard->recovery->witness, sample) ? result : CORE_WATCH_UNKNOWN;
}

static int no_surviving_core(const struct start_guard *guard, int busy_at_reservation)
{
    struct core_watch_sample current = {0};
    enum core_watch_state result = observe_unchanged(guard, &current);
    if (busy_at_reservation)
        return (result == CORE_WATCH_API_PORT_BUSY || result == CORE_WATCH_MISSING) &&
               core_watch_owner_childless(&current);
    return result == CORE_WATCH_MISSING &&
           (guard->recovery->witness.core || core_watch_owner_childless(&current)) &&
           core_watch_still_absent(&current);
}

static int still_missing(struct start_guard *guard)
{
    struct core_watch_sample observation = {0};
    if (*guard->stopping) return 0;
    /* v2rayA has no conditional start API. Recheck the live state before sending POST. */
    enum core_watch_state result = observe_unchanged(guard, &observation);
    int busy = result == CORE_WATCH_API_PORT_BUSY;
    if (!busy && result != CORE_WATCH_MISSING) return 0;

    /* Persist before the last live checks so file I/O cannot delay a checked start. */
    struct core_recovery previous = *guard->recovery;
    struct core_recovery reserved = previous;
    reserved.last_attempt = probe_clock_ms();
    ++reserved.attempts;
    if (!recovery_checkpoint_save(reserved.checkpoint, &reserved)) {
        guard->state_error = 1;
        return 0;
    }
    reserved.checkpoint_dirty = 0;
    *guard->recovery = reserved;

    char error[160] = {0};
    json_object *touch = v2raya_api_touch_data(guard->api, error, sizeof(error));
    json_object *running = json_object_object_get(touch, "running");
    int allows_start = json_object_is_type(running, json_type_boolean) && json_object_get_boolean(running) &&
                       !json_object_get_boolean(json_object_object_get(touch, "networkPaused"));
    json_object_put(touch);
    if (allows_start && !*guard->stopping)
        guard->port_error = unavailable_ports(guard->api, guard->config, &observation, guard->stopping);
    guard->request_allowed = allows_start && !guard->port_error && !*guard->stopping &&
                             no_surviving_core(guard, busy) && !*guard->stopping;
    if (!guard->request_allowed) {
        /* The API call stops before POST when this guard returns zero. Release the
         * reservation only after restoring its durable predecessor. */
        if (recovery_checkpoint_save(previous.checkpoint, &previous)) {
            previous.checkpoint_dirty = 0;
            *guard->recovery = previous;
        } else {
            guard->state_error = 1;
        }
    }
    return guard->request_allowed;
}

static int permit_start(void *context, char *remote_ip, char *local_ip, int remote_port, int local_port)
{
    struct start_guard *guard = context;
    struct core_watch_peer peer = {.api = guard->api->base, .stopping = guard->stopping,
                                   .expected = &guard->recovery->witness};
    return core_watch_verify_peer(&peer, remote_ip, local_ip, remote_port, local_port) || !still_missing(guard);
}

const char *core_recovery_tick(struct core_recovery *state, const struct v2raya_api *api,
                              const char *config_path, int intended_running,
                              const volatile sig_atomic_t *stopping)
{
    if (!intended_running) {
        int armed = state->witness.owner != 0;
        state->witness = (struct core_watch_sample){0};
        state->missing_since = 0;
        state->attempts = 0;
        if (armed || state->checkpoint_dirty) refresh_checkpoint(state);
        return NULL;
    }

    struct core_watch_sample observation = {0};
    json_object *config = node_config_read(config_path);
    enum core_watch_state result = core_watch_sample(api->base, config_path, config, &observation);
    int busy = result == CORE_WATCH_API_PORT_BUSY || result == CORE_WATCH_PORT_BUSY;
    if (result != CORE_WATCH_MISSING && !busy) {
        if (result == CORE_WATCH_HEALTHY) {
            int changed = observation.core != state->witness.core ||
                          !same_instance(&state->witness, &observation) || state->attempts;
            state->witness = observation;
            state->attempts = 0;
            if (changed || state->checkpoint_dirty) refresh_checkpoint(state);
        }
        state->missing_since = 0;
        json_object_put(config);
        return NULL;
    }

    const char *message = result == CORE_WATCH_API_PORT_BUSY ? "Xray API port is occupied" :
                          result == CORE_WATCH_PORT_BUSY ? "An Xray inbound port is occupied" :
                          "Xray recovery is waiting for confirmation";
    int64_t now = probe_clock_ms();
    if (state->checkpoint_required && !state->checkpoint) {
        message = "Xray is absent. Recovery state is unavailable";
    } else if (!confirm_witness(state, &observation, busy)) {
        state->missing_since = 0;
        message = "Xray is absent. Recovery could not rule out another process owned by v2rayA";
    } else if (!state->missing_since || now < state->missing_since) {
        state->missing_since = now;
    } else if (state->attempts >= CORE_RECOVERY_MAX_ATTEMPTS) {
        message = "Xray recovery exhausted its start attempts";
    } else if (now - state->missing_since >= confirmation_ms &&
               (!state->last_attempt || now - state->last_attempt >= recovery_pause_ms) && !*stopping) {
        char error[160] = {0};
        if (capability_check_api(api, FEATURE_CORE_START, error, sizeof(error)) == CAPABILITY_DENIED) {
            message = "Starting a crashed core is not verified for this v2rayA version";
        } else if (result != CORE_WATCH_PORT_BUSY) {
            const char *port_error = unavailable_ports(api, config, &observation, stopping);
            if (port_error) {
                json_object_put(config);
                return port_error;
            }
            struct start_guard guard = {.recovery = state, .api = api, .path = config_path,
                                        .config = config, .stopping = stopping};
            int rc = v2raya_api_start_core(api, permit_start, &guard, error, sizeof(error));
            if (guard.state_error) {
                message = "Xray is absent. Recovery state could not be saved";
            } else if (guard.port_error) {
                message = guard.port_error;
            } else if (guard.request_allowed) {
                message = rc ? "Xray recovery start was not acknowledged" : "Xray recovery start requested";
                fprintf(stderr, "v2raya-helper: %s\n", message);
            }
        }
    } else if (state->last_attempt) {
        message = "Xray recovery is waiting before another start attempt";
    }
    json_object_put(config);
    return message;
}
