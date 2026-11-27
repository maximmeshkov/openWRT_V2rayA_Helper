#define _GNU_SOURCE
#include "failover_monitor.h"
#include "boot_id.h"
#include "failover_api.h"
#include "failover_cooldown.h"
#include "failover_endpoint.h"
#include "failover_policy.h"
#include "failover_profile.h"
#include "node_profile.h"
#include "probe_core.h"
#include "latency_history.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

struct status {
    struct failover_streak streak;
    size_t next_candidate;
    time_t tried_sample;
    int ready, awaiting_sample;
};

struct failover_monitor {
    const char *path;
    char *lock_path, *last_path;
    char boot_id[BOOT_ID_LENGTH + 1];
    struct v2raya_api api;
    const struct https_options *https; /* the daemon's, updated every cycle */
    struct latency_history *history;
    uint32_t mark;
    json_object *settings;
    struct status *rows;
    size_t count, next_outbound;
    json_object *switch_config;
    size_t switched_row;
    char switched_key[FAILOVER_ID_LIMIT + 1];
};

int failover_lock_settings(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

struct failover_monitor *failover_monitor_create(const char *path, const struct v2raya_api *api,
    const struct https_options *https, uint32_t mark, struct latency_history *history)
{
    if (!path || !https->url) return NULL;
    struct failover_monitor *m = calloc(1, sizeof(*m));
    if (!m) return NULL;
    m->path = path;
    m->api = *api;
    m->https = https;
    m->history = history;
    m->mark = mark;
    boot_id_read(m->boot_id);
    if (asprintf(&m->lock_path, "%s.lock", path) < 0 ||
        asprintf(&m->last_path, "%s.last", path) < 0) {
        failover_monitor_free(m);
        return NULL;
    }
    return m;
}

void failover_monitor_free(struct failover_monitor *m)
{
    if (!m) return;
    free(m->lock_path);
    free(m->last_path);
    free(m->rows);
    json_object_put(m->settings);
    json_object_put(m->switch_config);
    free(m);
}

void failover_monitor_reset(struct failover_monitor *m)
{
    if (!m) return;
    if (m->rows) memset(m->rows, 0, m->count * sizeof(*m->rows));
    json_object_put(m->switch_config);
    m->switch_config = NULL;
}

static json_object *reload_policies(struct failover_monitor *m)
{
    json_object *settings = failover_settings_read(m->path);
    if (!settings) {
        failover_monitor_reset(m);
        return NULL;
    }
    if (!m->settings || !json_object_equal(settings, m->settings)) {
        json_object *policies = json_object_object_get(settings, "policies");
        size_t count = json_object_array_length(policies);
        struct status *rows = count ? calloc(count, sizeof(*rows)) : NULL;
        if (count && !rows) {
            json_object_put(settings);
            return NULL;
        }
        free(m->rows);
        m->rows = rows;
        m->count = count;
        json_object_put(m->settings);
        m->settings = settings;
    } else json_object_put(settings);
    return json_object_object_get(m->settings, "policies");
}

static const struct outbound *single_outbound(const struct inventory *inv, const char *name)
{
    for (size_t i = 0; i < inv->count; i++)
        if (inv->outbounds[i].count == 1 && !strcmp(inv->outbounds[i].name, name))
            return &inv->outbounds[i];
    return NULL;
}

void failover_monitor_config_changed(struct failover_monitor *m, const struct inventory *inv,
                                     json_object *previous, json_object *next)
{
    if (!m) return;
    if (!m->switch_config || !inv->running || !previous || !next ||
        !json_object_equal(m->switch_config, next)) {
        failover_monitor_reset(m);
        return;
    }
    json_object *policies = json_object_object_get(m->settings, "policies");
    struct failover_policy switched;
    if (failover_policy_parse(json_object_array_get_idx(policies, m->switched_row), &switched)) {
        failover_monitor_reset(m);
        return;
    }
    const struct outbound *updated = single_outbound(inv, switched.outbound);
    if (!updated || strcmp(updated->members[0].key, m->switched_key)) {
        failover_monitor_reset(m);
        return;
    }
    /* Keep only already qualified rows whose assignment and Xray outbound
     * did not change. A new check must confirm the condition after the switch. */
    for (size_t i = 0; i < m->count; i++) {
        struct status *status = &m->rows[i];
        struct failover_policy policy;
        if (i == m->switched_row || !status->ready ||
            failover_policy_parse(json_object_array_get_idx(policies, i), &policy)) {
            *status = (struct status){0};
            continue;
        }
        const struct outbound *out = single_outbound(inv, policy.outbound);
        const struct member *member = out ? &out->members[0] : NULL;
        json_object *old_outbound = member ? node_config_outbound(previous, out, member) : NULL;
        json_object *new_outbound = member ? node_config_outbound(next, out, member) : NULL;
        if (!member || strcmp(member->key, status->streak.id) || !old_outbound || !new_outbound ||
            !json_object_equal(old_outbound, new_outbound)) {
            *status = (struct status){0};
            continue;
        }
        status->ready = 0;
        status->awaiting_sample = 1;
    }
    json_object_put(m->switch_config);
    m->switch_config = NULL;
}

static enum failover_probe_state classify(const struct measurement *sample, long http_code)
{
    if (!sample->state || !sample->detail) return FAILOVER_UNKNOWN;
    if (!strcmp(sample->state, "ok")) return FAILOVER_OK;
    if (http_code || (strcmp(sample->state, "timeout") && strcmp(sample->state, "error")))
        return FAILOVER_UNKNOWN;
    /* Every failed HTTPS request through the server counts, TLS errors and
     * dropped streams included: through the probe core a dead server shows up
     * that way. Only the helper's own trouble says nothing about the server. */
    if (!strcmp(sample->detail, "probe_unavailable") || !strcmp(sample->detail, "https_mark_error"))
        return FAILOVER_UNKNOWN;
    return FAILOVER_FAILED;
}

static struct failover_sample active_sample(const struct member *member)
{
    return (struct failover_sample){.id = member->key, .state = classify(&member->https, member->http_code),
                                    .ms = member->https.ms, .checked = member->https.checked};
}

static struct failover_sample probe_candidate(struct failover_monitor *m, const struct failover_node *node,
    const struct failover_policy *policy, const char *link)
{
    struct report {
        struct measurement sample;
        long code;
    } result = {0};
    struct failover_profile profile = {0};
    if (failover_profile_parse(link, &profile)) return (struct failover_sample){0};
    if (policy->exclusions && json_object_array_length(policy->exclusions)) {
        /* Verify the actual probe endpoint as well as its catalogue identity. */
        char address[FAILOVER_ENDPOINT_LIMIT + 1], endpoint[FAILOVER_ENDPOINT_LIMIT + 1];
        const char *format = strchr(profile.node.host, ':') ? "[%s]:%d" : "%s:%d";
        int length = snprintf(address, sizeof(address), format, profile.node.host, profile.node.port);
        if (length < 0 || (size_t)length >= sizeof(address) ||
            !failover_endpoint_normalize(address, endpoint) || strcmp(endpoint, node->endpoint)) goto done;
    }
    int core_port = 0;
    pid_t core = profile.node.kind == NODE_CORE ?
                 probe_core_launch(&profile.node.outbound, 1, m->https, m->mark, &core_port) : -1;
    if (core < 0) core_port = 0;
    int channel[2];
    if (pipe2(channel, O_CLOEXEC | O_NONBLOCK) < 0) {
        probe_core_stop(core);
        goto done;
    }
    pid_t parent = getpid(), child = fork();
    if (!child) {
        close(channel[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != parent) _exit(1);
        result.sample = probe_https_profile(&profile.node, m->https, m->mark, core_port, &result.code);
        _exit(write(channel[1], &result, sizeof(result)) == sizeof(result) ? 0 : 1);
    }
    close(channel[1]);
    if (child > 0) {
        struct pollfd ready = {.fd = channel[0], .events = POLLIN};
        int polled = poll(&ready, 1, (int)(m->https->timeout * 1000 + 50));
        if (polled <= 0 || read(channel[0], &result, sizeof(result)) != sizeof(result)) {
            result = (struct report){0};
            kill(child, SIGKILL);
            if (!polled)
                result.sample = (struct measurement){.state = "timeout", .detail = "dns_or_probe_timeout",
                                                     .checked = time(NULL)};
        }
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    }
    close(channel[0]);
    probe_core_stop(core);
done:
    failover_profile_clear(&profile);
    latency_history_add(m->history, policy->outbound, node->name, node->key, &result.sample, "reserve");
    return (struct failover_sample){.state = classify(&result.sample, result.code), .ms = result.sample.ms,
                                    .checked = result.sample.checked};
}

struct switch_gate {
    struct failover_monitor *monitor;
    const struct failover_policy *policy;
    struct status *status;
    const struct failover_sample *active, *candidate;
    const char *config_path;
    json_object *config;
    time_t confirmed_at;
    long max_age;
    const volatile sig_atomic_t *stopping;
    int attempted;
};

static int permit_switch(void *opaque)
{
    struct switch_gate *gate = opaque;
    struct failover_monitor *m = gate->monitor;
    time_t now = time(NULL);
    long age = failover_cooldown_age(m->last_path, m->boot_id, now);
    if (*gate->stopping ||
        !failover_policy_confirmed(gate->policy, gate->active, &gate->status->streak,
                                   gate->candidate, gate->confirmed_at, now, gate->max_age, age))
        return 0;
    json_object *current = node_config_read(gate->config_path);
    int unchanged = current && json_object_equal(current, gate->config);
    json_object_put(current);
    if (!unchanged || *gate->stopping ||
        failover_cooldown_save(m->last_path, m->boot_id, now, gate->policy->cooldown_seconds))
        return 0;
    if (*gate->stopping) return 0;
    gate->attempted = 1;
    return 1;
}

struct candidate_pool {
    const struct failover_subscription *groups[FAILOVER_SELECTION_LIMIT];
    size_t group_count, explicit_count, total_count;
};

static struct candidate_pool selected_pool(const struct failover_catalogue *catalog,
                                           const struct failover_policy *policy)
{
    struct candidate_pool pool = {.explicit_count = json_object_array_length(policy->candidates)};
    pool.total_count = pool.explicit_count;
    size_t count = policy->subscriptions ? json_object_array_length(policy->subscriptions) : 0;
    for (size_t i = 0; i < count; i++) {
        const char *key = json_object_get_string(json_object_array_get_idx(policy->subscriptions, i));
        const struct failover_subscription *group = failover_catalogue_subscription(catalog, key);
        if (!group || !group->count) continue;
        pool.groups[pool.group_count++] = group;
        pool.total_count += group->count;
    }
    return pool;
}

static const struct failover_node *pool_candidate(const struct candidate_pool *pool,
    const struct failover_catalogue *catalog, const struct failover_policy *policy, size_t index,
    const char **subscription)
{
    *subscription = NULL;
    if (index < pool->explicit_count) {
        const char *key = json_object_get_string(json_object_array_get_idx(policy->candidates, index));
        return failover_catalogue_find(catalog, key);
    }
    index -= pool->explicit_count;
    for (size_t i = 0; i < pool->group_count; i++) {
        const struct failover_subscription *group = pool->groups[i];
        if (index >= group->count) {
            index -= group->count;
            continue;
        }
        const struct failover_node *node = &catalog->nodes[group->first + index];
        if (failover_policy_selects(policy, node->key, NULL) || failover_catalogue_find(catalog, node->key) != node)
            return NULL;
        *subscription = group->key;
        return node;
    }
    return NULL;
}

static time_t confirm_active(struct failover_monitor *m, const struct failover_policy *policy, struct status *status,
                             const struct outbound *out, const struct failover_sample *active, json_object *config)
{
    struct member checked = out->members[0];
    struct probe_job job = {.out = out, .member = &checked};
    probe_members(&job, 1, m->https->timeout * 1000, m->mark, m->https, config);
    struct failover_sample result = active_sample(&checked);
    if ((active->state == FAILOVER_FAILED && result.state == FAILOVER_FAILED) ||
        (active->state == FAILOVER_OK && result.state == FAILOVER_OK && result.ms > (long)policy->max_ms))
        return result.checked;

    /* The confirmation can veto a switch but cannot advance either streak. */
    status->ready = 0;
    status->streak.failed = status->streak.slow = 0;
    if (result.state == FAILOVER_UNKNOWN)
        status->streak.window_count = 0;
    return 0;
}

static int switch_candidate(struct failover_monitor *m, const struct failover_policy *policy,
    struct status *status, const struct outbound *out, const struct failover_sample *active, long max_age,
    const char *config_path, json_object *config, const volatile sig_atomic_t *stopping)
{
    const struct member *member = &out->members[0];
    char error[160] = {0};
    struct failover_catalogue catalog = {0};
    int attempted = 0;
    if (failover_catalogue_read(&m->api, &catalog, error, sizeof(error)) || !catalog.running)
        goto done;
    const struct failover_node *current = NULL;
    for (size_t i = 0; i < catalog.count; i++) {
        const struct failover_node *node = &catalog.nodes[i];
        if (node->id == member->node_id && node->sub == member->subscription &&
            !strcmp(node->key, member->key)) current = node;
    }
    if (!current) goto done;
    struct candidate_pool pool = selected_pool(&catalog, policy);
    for (size_t i = 0; i < pool.total_count && !*stopping; i++) {
        size_t index = status->next_candidate++ % pool.total_count;
        const char *subscription;
        const struct failover_node *candidate = pool_candidate(&pool, &catalog, policy, index, &subscription);
        if (!candidate || candidate == current || failover_policy_excludes(policy, candidate->endpoint)) continue;
        char *link = failover_api_profile(&m->api, candidate, error, sizeof(error));
        if (!link) break;
        struct failover_sample result = probe_candidate(m, candidate, policy, link);
        if (!result.checked) {
            /* No probe ran: a protocol the probe cannot run, or an endpoint that moved.
             * Try the next reserve now rather than spend this turn on it. */
            free(link);
            continue;
        }
        result.id = candidate->key;
        result.subscription = subscription;
        result.endpoint = candidate->endpoint;
        time_t now = time(NULL);
        long age = failover_cooldown_age(m->last_path, m->boot_id, now);
        time_t confirmed_at = 0;
        if (!*stopping &&
            failover_policy_choose(policy, active, &status->streak, &result, 1, now, max_age, age))
            confirmed_at = confirm_active(m, policy, status, out, active, config);
        int lock = confirmed_at && !*stopping ? failover_lock_settings(m->lock_path) : -1;
        if (lock >= 0) {
            json_object *fresh = failover_settings_read(m->path);
            now = time(NULL);
            age = failover_cooldown_age(m->last_path, m->boot_id, now);
            if (fresh && json_object_equal(fresh, m->settings) &&
                failover_policy_confirmed(policy, active, &status->streak, &result, confirmed_at, now, max_age, age)) {
                struct switch_gate gate = {.monitor = m, .policy = policy, .status = status,
                    .active = active, .candidate = &result, .config_path = config_path,
                    .config = config, .confirmed_at = confirmed_at, .max_age = max_age, .stopping = stopping};
                int rc = failover_api_connect(&m->api, policy->outbound, current, candidate, link, subscription,
                                               permit_switch, &gate, error, sizeof(error));
                attempted = gate.attempted;
                if (attempted) {
                    fprintf(stderr, "v2raya-helper: automatic server switch %s\n",
                            rc ? "was not confirmed" : "was confirmed");
                    json_object *next = rc ? NULL : node_config_read(config_path);
                    if (next && !json_object_equal(config, next)) {
                        json_object_put(m->switch_config);
                        m->switch_config = next;
                        m->switched_row = (size_t)(status - m->rows);
                        snprintf(m->switched_key, sizeof(m->switched_key), "%s", candidate->key);
                    } else {
                        json_object_put(next);
                        failover_monitor_reset(m);
                    }
                }
            }
            json_object_put(fresh);
            close(lock);
        }
        free(link);
        break;
    }
done:
    failover_catalogue_free(&catalog);
    return attempted;
}

int failover_monitor_tick(struct failover_monitor *m, const struct inventory *inv,
                          const char *config_path, json_object *config, const volatile sig_atomic_t *stopping)
{
    if (!m) return 0;
    if (!inv || !inv->running || !config || m->switch_config) {
        /* An unmatched confirmation means the following discovery did not
         * observe the expected configuration transition. */
        failover_monitor_reset(m);
        return 0;
    }
    json_object *policies = reload_policies(m);
    if (!policies || !m->count) return 0;
    long max_age = 2 * m->https->interval + m->https->timeout;
    time_t now = time(NULL);
    long age = failover_cooldown_age(m->last_path, m->boot_id, now);
    if (age == FAILOVER_COOLDOWN_LEGACY_FUTURE || age == FAILOVER_COOLDOWN_EXPIRED) {
        int lock = failover_lock_settings(m->lock_path);
        if (lock >= 0) {
            failover_cooldown_maintain(m->last_path, m->boot_id, now);
            close(lock);
            age = failover_cooldown_age(m->last_path, m->boot_id, now);
        }
    }
    /* Evaluate every enabled row before the first attempt can restart Xray. */
    for (size_t i = 0; i < m->count && !*stopping; i++) {
        struct status *status = &m->rows[i];
        status->ready = 0;
        struct failover_policy policy;
        if (failover_policy_parse(json_object_array_get_idx(policies, i), &policy) ||
            policy.mode == FAILOVER_OFF) continue;
        const struct outbound *out = single_outbound(inv, policy.outbound);
        if (!out) {
            *status = (struct status){0};
            continue;
        }
        const struct member *member = &out->members[0];
        struct failover_sample active = active_sample(member);
        if (status->awaiting_sample) {
            if (!strcmp(member->key, status->streak.id) && !active.checked && member->https.state &&
                !strcmp(member->https.state, "pending") && status->streak.checked <= now)
                continue;
            status->awaiting_sample = 0;
            if (active.checked <= status->streak.checked)
                *status = (struct status){0};
        }
        failover_record(&status->streak, &policy, &active, now, max_age);
        status->ready = failover_policy_ready(&policy, &active, &status->streak, now, max_age, age);
    }
    /* Return to inventory and core recovery before probing another outbound. */
    size_t first = m->next_outbound;
    int checked_row = 0;
    for (size_t offset = 0; offset < m->count && !*stopping; offset++) {
        size_t i = (first + offset) % m->count;
        struct status *status = &m->rows[i];
        if (!status->ready) continue;
        struct failover_policy policy;
        if (failover_policy_parse(json_object_array_get_idx(policies, i), &policy)) continue;
        const struct outbound *out = single_outbound(inv, policy.outbound);
        if (!out) continue;
        const struct member *member = &out->members[0];
        struct failover_sample active = active_sample(member);
        if (status->tried_sample == active.checked) continue;
        if (checked_row) return 1;
        checked_row = 1;
        status->tried_sample = active.checked;
        m->next_outbound = (i + 1) % m->count;
        if (switch_candidate(m, &policy, status, out, &active, max_age, config_path, config, stopping)) break;
    }
    return 0;
}
