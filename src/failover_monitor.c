#define _GNU_SOURCE
#include "failover_monitor.h"
#include "failover_api.h"
#include "failover_policy.h"
#include "failover_profile.h"
#include "node_profile.h"
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
    struct v2raya_api api;
    struct https_options https;
    struct latency_history *history;
    uint32_t mark;
    json_object *settings;
    struct status *rows;
    size_t count;
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
    m->https = *https;
    m->history = history;
    m->mark = mark;
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

static time_t last_attempt(const char *path, time_t now)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    char buffer[64];
    ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (n <= 0 || n >= (ssize_t)sizeof(buffer)-1) return -1;
    buffer[n] = '\0';
    char *end, *tail;
    errno = 0;
    long long value = strtoll(buffer, &end, 10);
    if (errno || *end != ' ' || value <= 0) return -1;
    long long unblock = strtoll(end+1, &tail, 10);
    if (errno || tail != buffer+n-1 || *tail != '\n' || unblock < value || unblock-value > 86400)
        return -1;
    /* Even a shorter policy on another outbound must honor this pause. */
    return now < (time_t)unblock ? -1 : (time_t)value;
}

static int record_attempt(const char *path, time_t when, unsigned cooldown)
{
    char *temp = NULL;
    if (asprintf(&temp, "%s.XXXXXX", path) < 0) return -1;
    int fd = mkstemp(temp);
    int rc = -1;
    if (fd >= 0) {
        int written = dprintf(fd, "%lld %lld\n", (long long)when, (long long)when+cooldown);
        if (written > 0 && fsync(fd)) written = -1;
        if (!close(fd) && written > 0) rc = rename(temp, path);
        if (rc) unlink(temp);
    }
    free(temp);
    return rc;
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
    if (!strcmp(sample->state, "timeout") || !strcmp(sample->detail, "https_timeout") ||
        !strcmp(sample->detail, "xhttp_session_failed") || !strcmp(sample->detail, "https_connect_error") ||
        !strcmp(sample->detail, "https_proxy_error"))
        return FAILOVER_FAILED;
    return FAILOVER_UNKNOWN;
}

static struct failover_sample active_sample(const struct member *member)
{
    return (struct failover_sample){.id = member->key, .state = classify(&member->https, member->http_code),
                                    .ms = member->https.ms, .checked = member->https.checked};
}

static struct failover_sample probe_candidate(struct failover_monitor *m, const struct failover_node *node,
    const char *outbound, const char *link)
{
    struct report {
        struct measurement sample;
        long code;
    } result = {0};
    struct failover_profile profile = {0};
    if (failover_profile_parse(link, &profile)) return (struct failover_sample){0};
    int channel[2];
    if (pipe2(channel, O_CLOEXEC | O_NONBLOCK) < 0) goto done;
    pid_t parent = getpid(), child = fork();
    if (!child) {
        close(channel[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != parent) _exit(1);
        result.sample = probe_https_profile(&profile.node, &m->https, m->mark, &result.code);
        _exit(write(channel[1], &result, sizeof(result)) == sizeof(result) ? 0 : 1);
    }
    close(channel[1]);
    if (child > 0) {
        struct pollfd ready = {.fd = channel[0], .events = POLLIN};
        int polled = poll(&ready, 1, (int)(m->https.timeout * 1000 + 50));
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
done:
    failover_profile_clear(&profile);
    latency_history_add(m->history, outbound, node->name, node->key, &result.sample, "reserve");
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
    long max_age;
    int attempted;
};

static int permit_switch(void *opaque)
{
    struct switch_gate *gate = opaque;
    time_t now = time(NULL), last = last_attempt(gate->monitor->last_path, now);
    if (last < 0 ||
        !failover_policy_choose(gate->policy, gate->active, &gate->status->streak,
                                gate->candidate, 1, now, gate->max_age, last))
        return 0;
    json_object *current = node_config_read(gate->config_path);
    int unchanged = current && json_object_equal(current, gate->config);
    json_object_put(current);
    if (!unchanged || record_attempt(gate->monitor->last_path, now, gate->policy->cooldown_seconds))
        return 0;
    gate->attempted = 1;
    return 1;
}

static int switch_candidate(struct failover_monitor *m, const struct failover_policy *policy,
    struct status *status, const struct member *member, const struct failover_sample *active, long max_age,
    const char *config_path, json_object *config)
{
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
    size_t count = json_object_array_length(policy->candidates);
    for (size_t i = 0; i < count; i++) {
        size_t index = status->next_candidate++ % count;
        const char *key = json_object_get_string(json_object_array_get_idx(policy->candidates, index));
        const struct failover_node *candidate = failover_catalogue_find(&catalog, key);
        if (!candidate || (candidate->id == current->id && candidate->sub == current->sub))
            continue;
        char *link = failover_api_profile(&m->api, candidate, error, sizeof(error));
        if (!link) continue;
        struct failover_sample result = probe_candidate(m, candidate, policy->outbound, link);
        result.id = key;
        int lock = failover_lock_settings(m->lock_path);
        if (lock >= 0) {
            json_object *fresh = failover_settings_read(m->path);
            time_t now = time(NULL), last = last_attempt(m->last_path, now);
            if (fresh && last >= 0 && json_object_equal(fresh, m->settings) &&
                failover_policy_choose(policy, active, &status->streak, &result, 1, now, max_age, last)) {
                struct switch_gate gate = {.monitor = m, .policy = policy, .status = status,
                    .active = active, .candidate = &result, .config_path = config_path,
                    .config = config, .max_age = max_age};
                int rc = failover_api_connect(&m->api, policy->outbound, current, candidate, link,
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

void failover_monitor_tick(struct failover_monitor *m, const struct inventory *inv,
                           const char *config_path, json_object *config)
{
    if (!m) return;
    if (!inv || !inv->running || !config || m->switch_config) {
        /* An unmatched confirmation means the following discovery did not
         * observe the expected configuration transition. */
        failover_monitor_reset(m);
        return;
    }
    json_object *policies = reload_policies(m);
    if (!policies || !m->count) return;
    long max_age = 2 * m->https.interval + m->https.timeout;
    time_t now = time(NULL), last = last_attempt(m->last_path, now);
    /* Evaluate every enabled row before the first attempt can restart Xray. */
    for (size_t i = 0; i < m->count; i++) {
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
                !strcmp(member->https.state, "pending") && status->streak.checked <= now &&
                difftime(now, status->streak.checked) <= max_age)
                continue;
            status->awaiting_sample = 0;
            if (active.checked <= status->streak.checked)
                *status = (struct status){0};
        }
        failover_record(&status->streak, &policy, &active, now, max_age);
        status->ready = last >= 0 && failover_policy_ready(&policy, &active, &status->streak, now, max_age, last);
    }
    for (size_t i = 0; i < m->count; i++) {
        struct status *status = &m->rows[i];
        if (!status->ready) continue;
        struct failover_policy policy;
        if (failover_policy_parse(json_object_array_get_idx(policies, i), &policy)) continue;
        const struct outbound *out = single_outbound(inv, policy.outbound);
        if (!out) continue;
        const struct member *member = &out->members[0];
        struct failover_sample active = active_sample(member);
        if (status->tried_sample == active.checked) continue;
        status->tried_sample = active.checked;
        if (switch_candidate(m, &policy, status, member, &active, max_age, config_path, config)) break;
    }
}
