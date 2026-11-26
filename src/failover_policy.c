#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "failover_endpoint.h"
#include "failover_policy.h"
#include "utf8.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { SETTINGS_LIMIT = 256 * 1024, POLICY_LIMIT = 128 };

static const char *read_string(json_object *value)
{
    if (!json_object_is_type(value, json_type_string)) return NULL;
    const char *s = json_object_get_string(value);
    return strlen(s) == (size_t)json_object_get_string_len(value) ? s : NULL;
}

static const char *field(json_object *obj, const char *name)
{
    return read_string(json_object_object_get(obj, name));
}

static int valid_id(const char *id)
{
    static const char allowed[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_.:";
    return id && *id && strlen(id) <= FAILOVER_ID_LIMIT && strspn(id, allowed) == strlen(id);
}

static int canonical_endpoint(const char *endpoint)
{
    char normalized[FAILOVER_ENDPOINT_LIMIT + 1];
    return endpoint && failover_endpoint_normalize(endpoint, normalized) && !strcmp(endpoint, normalized);
}

static int valid_outbound(const char *name)
{
    if (!name || !*name || strlen(name) > 255) return 0;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++)
        if (*p < 32 || *p == 127) return 0;
    return 1;
}

static int number(json_object *obj, const char *name, unsigned *out, unsigned min, unsigned max)
{
    json_object *value = NULL;
    if (!json_object_object_get_ex(obj, name, &value)) return 1;
    if (!json_object_is_type(value, json_type_int)) return 0;
    int64_t n = json_object_get_int64(value);
    if (n < min || n > max) return 0;
    *out = (unsigned)n;
    return 1;
}

static int digit(char c)
{
    return c >= '0' && c <= '9';
}

static int minute(const char *s, unsigned *out)
{
    if (!s || strlen(s) != 5 || s[2] != ':' || !digit(s[0]) || !digit(s[1]) ||
        !digit(s[3]) || !digit(s[4]))
        return 0;
    int h = (s[0] - '0') * 10 + s[1] - '0', m = (s[3] - '0') * 10 + s[4] - '0';
    if (h >= 24 || m >= 60) return 0;
    *out = 60u * (unsigned)h + (unsigned)m;
    return 1;
}

static int checked_keys(json_object *keys, int (*valid)(const char *))
{
    if (!json_object_is_type(keys, json_type_array)) return 0;
    size_t count = json_object_array_length(keys);
    if (count > FAILOVER_SELECTION_LIMIT) return 0;
    for (size_t i = 0; i < count; i++) {
        const char *id = read_string(json_object_array_get_idx(keys, i));
        if (!valid(id)) return 0;
        for (size_t j = 0; j < i; j++)
            if (!strcmp(id, read_string(json_object_array_get_idx(keys, j)))) return 0;
    }
    return 1;
}

int failover_policy_parse(json_object *entry, struct failover_policy *policy)
{
    if (!json_object_is_type(entry, json_type_object) || !policy) return -1;
    *policy = (struct failover_policy) {
        .outbound = field(entry, "outbound"),
        .candidates = json_object_object_get(entry, "candidates"),
        .failures = FAILOVER_DEFAULT_FAILURES,
        .cooldown_seconds = FAILOVER_DEFAULT_COOLDOWN,
        .failure_method = FAILOVER_CONSECUTIVE,
        .failure_window_minutes = FAILOVER_DEFAULT_WINDOW_MINUTES,
    };
    const char *mode = field(entry, "mode");
    if (!mode || !valid_outbound(policy->outbound) || !checked_keys(policy->candidates, valid_id) ||
        (json_object_object_get_ex(entry, "subscriptions", &policy->subscriptions) &&
         !checked_keys(policy->subscriptions, valid_id)) ||
        (json_object_object_get_ex(entry, "exclusions", &policy->exclusions) &&
         !checked_keys(policy->exclusions, canonical_endpoint)))
        return -1;
    if (!strcmp(mode, "off")) policy->mode = FAILOVER_OFF;
    else if (!strcmp(mode, "outage")) policy->mode = FAILOVER_OUTAGE;
    else if (!strcmp(mode, "scheduled")) policy->mode = FAILOVER_SCHEDULED;
    else return -1;

    json_object *method;
    if (json_object_object_get_ex(entry, "failure_method", &method)) {
        const char *name = read_string(method);
        if (!name) return -1;
        if (!strcmp(name, "window")) policy->failure_method = FAILOVER_WINDOW;
        else if (strcmp(name, "consecutive")) return -1;
    }
    if (!number(entry, "failures", &policy->failures, FAILOVER_DEFAULT_FAILURES, FAILOVER_MAX_FAILURES) ||
        !number(entry, "failure_window_minutes", &policy->failure_window_minutes, 1, 180) ||
        !number(entry, "max_ms", &policy->max_ms, 0, 60000) ||
        !number(entry, "cooldown_seconds", &policy->cooldown_seconds, 60, 86400))
        return -1;
    if (policy->mode == FAILOVER_SCHEDULED &&
        (!minute(field(entry, "start"), &policy->start_minute) ||
         !minute(field(entry, "end"), &policy->end_minute) ||
         policy->start_minute == policy->end_minute))
        return -1;
    return 0;
}

static int valid_settings(json_object *settings)
{
    if (!json_object_is_type(settings, json_type_object)) return 0;
    json_object *entries = json_object_object_get(settings, "policies");
    if (!json_object_is_type(entries, json_type_array)) return 0;
    size_t count = json_object_array_length(entries);
    if (count > POLICY_LIMIT) return 0;
    for (size_t i = 0; i < count; i++) {
        struct failover_policy policy;
        if (failover_policy_parse(json_object_array_get_idx(entries, i), &policy)) return 0;
        for (size_t j = 0; j < i; j++)
            if (!strcmp(policy.outbound, field(json_object_array_get_idx(entries, j), "outbound"))) return 0;
    }
    return 1;
}

static json_object *read_fd(int fd)
{
    struct stat s;
    if (fstat(fd, &s) || !S_ISREG(s.st_mode) || s.st_size <= 0 || s.st_size > SETTINGS_LIMIT)
        return NULL;
    size_t length = (size_t)s.st_size, used = 0;
    char *buf = malloc(length + 1);
    if (!buf) return NULL;
    json_object *settings = NULL;
    while (used < length + 1) {
        ssize_t n = read(fd, buf + used, length + 1 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) goto done;
        if (!n) break;
        used += (size_t)n;
    }
    if (used == length) settings = parse_utf8_json(buf, length);
    if (!valid_settings(settings)) {
        json_object_put(settings);
        settings = NULL;
    }
done:
    free(buf);
    return settings;
}

json_object *failover_settings_read(const char *path)
{
    if (!path || !*path) return NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 && errno == ENOENT) {
        json_object *settings = json_object_new_object(), *policies = json_object_new_array();
        if (!settings || !policies) {
            json_object_put(settings);
            json_object_put(policies);
            return NULL;
        }
        json_object_object_add(settings, "policies", policies);
        return settings;
    }
    if (fd < 0) return NULL;
    json_object *settings = read_fd(fd);
    close(fd);
    return settings;
}

int failover_settings_write(const char *path, json_object *settings)
{
    if (!path || !*path || !valid_settings(settings)) return -1;
    const char *encoded = json_object_to_json_string_ext(settings, JSON_C_TO_STRING_PLAIN);
    if (!encoded || strlen(encoded) > SETTINGS_LIMIT) return -1;
    size_t size = strlen(path) + sizeof(".XXXXXX");
    char *tmp = malloc(size);
    if (!tmp) return -1;
    snprintf(tmp, size, "%s.XXXXXX", path);
    int fd = mkstemp(tmp);
    int status = -1;
    if (fd >= 0) {
        int written = json_object_to_fd(fd, settings, JSON_C_TO_STRING_PLAIN);
        if (!written) written = fsync(fd);
        int closed = close(fd);
        if (!written && !closed) status = rename(tmp, path);
        if (status) unlink(tmp);
    }
    free(tmp);
    return status;
}

static int fresh(const struct failover_sample *sample, time_t now, long age)
{
    return sample && sample->checked > 0 && sample->checked <= now && age >= 0 &&
           difftime(now, sample->checked) <= age;
}

static unsigned expired_failures(const struct failover_streak *streak,
                                 const struct failover_policy *policy, time_t now)
{
    unsigned expired = 0;
    while (expired < streak->window_count &&
           difftime(now, streak->failure_times[expired]) > policy->failure_window_minutes * 60u)
        expired++;
    return expired;
}

static void record_window_failure(struct failover_streak *streak,
                                  const struct failover_policy *policy, time_t at, time_t now)
{
    unsigned discard = expired_failures(streak, policy, now);
    if (!discard && streak->window_count == FAILOVER_MAX_FAILURES) discard = 1;
    if (discard) {
        streak->window_count -= discard;
        memmove(streak->failure_times, streak->failure_times + discard,
                streak->window_count * sizeof(*streak->failure_times));
    }
    if (difftime(now, at) <= policy->failure_window_minutes * 60u)
        streak->failure_times[streak->window_count++] = at;
}

void failover_record(struct failover_streak *streak, const struct failover_policy *policy,
                     const struct failover_sample *active, time_t now, long maximum_age)
{
    if (!streak || !policy) return;
    if (!fresh(active, now, maximum_age) || !valid_id(active->id) ||
        (active->state != FAILOVER_FAILED && (active->state != FAILOVER_OK || active->ms < 0))) {
        *streak = (struct failover_streak){0};
        return;
    }
    if (policy->mode == FAILOVER_OFF || strcmp(streak->id, active->id) || streak->checked > now)
        *streak = (struct failover_streak){0};
    if (policy->mode == FAILOVER_OFF || active->checked <= streak->checked) return;
    if (streak->checked && difftime(active->checked, streak->checked) > maximum_age)
        streak->failed = streak->slow = 0;
    memcpy(streak->id, active->id, strlen(active->id) + 1);
    streak->checked = active->checked;
    streak->latest = active->state;
    if (active->state == FAILOVER_FAILED) {
        if (streak->failed < policy->failures) streak->failed++;
        if (policy->failure_method == FAILOVER_WINDOW)
            record_window_failure(streak, policy, active->checked, now);
        streak->slow = 0;
        return;
    }
    streak->failed = 0;
    if (policy->mode == FAILOVER_SCHEDULED && policy->max_ms && active->ms > (long)policy->max_ms) {
        if (streak->slow < policy->failures) streak->slow++;
    } else {
        streak->slow = 0;
    }
}

static int window_open(const struct failover_policy *policy, time_t now)
{
    struct tm local;
    if (!localtime_r(&now, &local)) return 0;
    unsigned m = 60u * (unsigned)local.tm_hour + (unsigned)local.tm_min;
    if (policy->start_minute < policy->end_minute)
        return m >= policy->start_minute && m < policy->end_minute;
    return m >= policy->start_minute || m < policy->end_minute;
}

static int listed(json_object *keys, const char *key)
{
    if (!keys || !key) return 0;
    for (size_t i = 0; i < json_object_array_length(keys); i++)
        if (!strcmp(key, read_string(json_object_array_get_idx(keys, i)))) return 1;
    return 0;
}

int failover_policy_selects(const struct failover_policy *policy, const char *id, const char *subscription)
{
    return listed(policy->candidates, id) || listed(policy->subscriptions, subscription);
}

int failover_policy_excludes(const struct failover_policy *policy, const char *endpoint)
{
    return policy->exclusions && json_object_array_length(policy->exclusions) &&
           (!canonical_endpoint(endpoint) || listed(policy->exclusions, endpoint));
}

int failover_policy_ready(const struct failover_policy *policy,
                const struct failover_sample *active, const struct failover_streak *streak,
                time_t now, long maximum_age, time_t last_switch)
{
    if (!policy || !streak || policy->mode == FAILOVER_OFF ||
        (!json_object_array_length(policy->candidates) &&
         (!policy->subscriptions || !json_object_array_length(policy->subscriptions))) ||
        !fresh(active, now, maximum_age) || !valid_id(active->id) ||
        strcmp(active->id, streak->id) || active->checked != streak->checked || active->state != streak->latest ||
        (last_switch && difftime(now, last_switch) < policy->cooldown_seconds) ||
        (policy->mode == FAILOVER_SCHEDULED && !window_open(policy, now)))
        return 0;

    unsigned failures = policy->failure_method == FAILOVER_WINDOW ?
        streak->window_count - expired_failures(streak, policy, now) : streak->failed;
    int failed = active->state == FAILOVER_FAILED && failures >= policy->failures;
    int slow = policy->mode == FAILOVER_SCHEDULED && policy->max_ms &&
        active->state == FAILOVER_OK && active->ms > (long)policy->max_ms &&
        streak->slow >= policy->failures;
    return failed || slow;
}

const char *failover_policy_choose(const struct failover_policy *policy,
                const struct failover_sample *active, const struct failover_streak *streak,
                const struct failover_sample *samples, size_t count, time_t now,
                long maximum_age, time_t last_switch)
{
    if (!samples || !failover_policy_ready(policy, active, streak, now, maximum_age, last_switch))
        return NULL;

    const struct failover_sample *best = NULL;
    for (size_t i = 0; i < count; i++) {
        const struct failover_sample *sample = &samples[i];
        if (!valid_id(sample->id) || !strcmp(sample->id, active->id) ||
            !failover_policy_selects(policy, sample->id, sample->subscription) ||
            failover_policy_excludes(policy, sample->endpoint) ||
            sample->state != FAILOVER_OK || sample->ms < 0 || !fresh(sample, now, maximum_age) ||
            sample->checked < active->checked ||
            (active->state == FAILOVER_OK && sample->ms > (long)policy->max_ms))
            continue;
        if (!best || sample->ms < best->ms) best = sample;
    }
    return best ? best->id : NULL;
}
