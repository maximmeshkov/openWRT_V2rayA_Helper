#define _POSIX_C_SOURCE 200809L
#include "helper.h"
#include <curl/curl.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;

static void stop(int sig)
{
    (void)sig;
    stopping = 1;
}

static json_object *timestamp(time_t t)
{
    char buf[32];
    struct tm utc;
    if (!gmtime_r(&t, &utc) || !strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc))
        return NULL;
    return json_object_new_string(buf);
}

static void add_string(json_object *o, const char *key, const char *value)
{
    json_object_object_add(o, key, json_object_new_string(value));
}

static json_object *serialize_measure(struct measurement m, time_t now, long ttl)
{
    json_object *o = json_object_new_object();
    if (m.checked) json_object_object_add(o, "checked_at", timestamp(m.checked));
    if (m.checked && (m.checked > now || now - m.checked > ttl)) {
        add_string(o, "state", "unknown");
        add_string(o, "detail", "expired");
        return o;
    }
    add_string(o, "state", m.state ? m.state : "unknown");
    if (m.detail) add_string(o, "detail", m.detail);
    if (m.state && !strcmp(m.state, "ok"))
        json_object_object_add(o, "ms", json_object_new_int64(m.ms));
    return o;
}

static int publish(const char *path, const struct inventory *inv, const char *state,
                   const char *message, long ttl, long route_ttl)
{
    time_t now = time(NULL);
    int valid = strcmp(state, "ok") == 0;
    struct measurement unavailable = {.state = "unknown", .detail = "inventory_unavailable"};
    json_object *doc = json_object_new_object(), *rows = json_object_new_array();
    add_string(doc, "state", state);
    if (message && *message) add_string(doc, "message", message);
    json_object_object_add(doc, "updated_at", timestamp(now));
    json_object_object_add(doc, "fresh_until", timestamp(now + ttl));
    json_object_object_add(doc, "outbounds", rows);
    for (size_t i = 0; i < inv->count; ++i) {
        const struct outbound *out = &inv->outbounds[i];
        json_object *row = json_object_new_object(), *members = json_object_new_array();
        add_string(row, "name", out->name);
        json_object_object_add(row, "members", members);
        json_object_object_add(row, "route", serialize_measure(valid ? out->route : unavailable, now, route_ttl));
        for (size_t j = 0; j < out->count; ++j) {
            const struct member *m = &out->members[j];
            json_object *entry = json_object_new_object();
            add_string(entry, "name", m->name);
            add_string(entry, "address", m->address);
            add_string(entry, "transport", m->transport);
            json_object_object_add(entry, "selected", json_object_new_boolean(m->selected));
            json_object_object_add(entry, "server", serialize_measure(valid ? m->server : unavailable, now, ttl));
            json_object_array_add(members, entry);
        }
        json_object_array_add(rows, row);
    }

    size_t len = strlen(path) + sizeof(".XXXXXX");
    char *tmp = malloc(len);
    int rc = -1;
    if (tmp) {
        snprintf(tmp, len, "%s.XXXXXX", path);
        int fd = mkstemp(tmp);
        if (fd >= 0) {
            int written = json_object_to_fd(fd, doc, JSON_C_TO_STRING_PLAIN);
            if (close(fd) == 0 && written == 0) rc = rename(tmp, path);
            if (rc != 0) unlink(tmp);
        }
        free(tmp);
    }
    json_object_put(doc);
    if (rc != 0) perror("v2raya-helper: writing snapshot");
    return rc;
}

static int same_assignment(const struct outbound *a, const struct outbound *b)
{
    if (a->count != b->count || strcmp(a->name, b->name)) return 0;
    for (size_t j = 0; j < a->count; ++j) {
        const struct member *x = &a->members[j], *y = &b->members[j];
        if (strcmp(x->name, y->name) || strcmp(x->address, y->address) ||
            strcmp(x->display_net, y->display_net) || x->node_id != y->node_id ||
            x->subscription != y->subscription || x->selected != y->selected)
            return 0;
    }
    return 1;
}

static int can_probe(const struct member *m)
{
    return !strcmp(m->transport, "tcp") || !strcmp(m->transport, "quic");
}

/* Carry results across a successful discovery only for the same assignment. */
static void replace_inventory(struct inventory *old, struct inventory *next, int trusted)
{
    time_t now = time(NULL);
    for (size_t i = 0; i < next->count; ++i) {
        struct outbound *out = &next->outbounds[i];
        out->since = now;
        for (size_t j = 0; j < out->count; ++j) {
            struct member *m = &out->members[j];
            m->server.state = can_probe(m) ? "pending" : "unsupported";
        }
        if (!trusted || !next->running || !old->running) continue;
        for (size_t k = 0; k < old->count; ++k) {
            const struct outbound *prev = &old->outbounds[k];
            if (!same_assignment(out, prev)) continue;
            out->since = prev->since;
            out->route = prev->route;
            for (size_t j = 0; j < out->count; ++j)
                out->members[j].server = prev->members[j].server;
            break;
        }
    }
    free_inventory(old);
    *old = *next;
    *next = (struct inventory){0};
}

/* Select the oldest due tests so a slow large installation makes progress. */
static size_t pick_jobs(struct inventory *inv, struct member **jobs, size_t limit,
                        long interval, int *backlog)
{
    size_t count = 0;
    time_t now = time(NULL);
    *backlog = 0;
    for (size_t i = 0; i < inv->count; ++i) {
        struct outbound *out = &inv->outbounds[i];
        for (size_t j = 0; j < out->count; ++j) {
            struct member *m = &out->members[j];
            if (!can_probe(m)) continue;
            time_t checked = m->server.checked;
            if (checked && checked <= now && now - checked < interval) continue;
            size_t pos = count;
            if (count == limit) {
                *backlog = 1;
                if (jobs[count-1]->server.checked <= checked) continue;
                pos--;
            } else {
                count++;
            }
            while (pos && jobs[pos-1]->server.checked > checked) {
                jobs[pos] = jobs[pos-1];
                pos--;
            }
            jobs[pos] = m;
        }
    }
    return count;
}

static long number(const char *s, unsigned long min, unsigned long max)
{
    char *end;
    errno = 0;
    unsigned long n = strtoul(s, &end, 0);
    if (errno || !*s || *s == '-' || *end || n < min || n > max) {
        fprintf(stderr, "invalid numeric argument: %s\n", s);
        exit(2);
    }
    return (long)n;
}

int main(int argc, char **argv)
{
    const char *api = "http://127.0.0.1:2017", *token = NULL, *metrics = NULL;
    const char *output = "/var/run/v2raya-helper/status.json";
    long interval = 10, timeout = 3, workers = 2, route_ttl = 60;
    uint32_t mark = 0x80;
    static const struct option options[] = {
        {"api",1,0,'a'}, {"token-file",1,0,'t'}, {"observatory",1,0,'o'},
        {"output",1,0,'f'}, {"interval",1,0,'i'}, {"timeout",1,0,'d'},
        {"workers",1,0,'w'}, {"mark",1,0,'m'}, {"observatory-max-age",1,0,'e'},
        {"help",0,0,'h'}, {0,0,0,0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "", options, NULL)) != -1) {
        switch (opt) {
        case 'a': api = optarg; break;
        case 't': token = optarg; break;
        case 'o': metrics = optarg; break;
        case 'f': output = optarg; break;
        case 'i': interval = number(optarg, 1, 86400); break;
        case 'd': timeout = number(optarg, 1, 60); break;
        case 'w': workers = number(optarg, 1, 16); break;
        case 'm': mark = (uint32_t)number(optarg, 0, UINT32_MAX); break;
        case 'e': route_ttl = number(optarg, 1, 86400); break;
        case 'h':
            puts("v2raya-helper [--api URL] [--token-file PATH] [--output PATH]\n"
                 "  [--interval SECONDS] [--timeout SECONDS] [--workers 1..16] [--mark N]\n"
                 "  [--observatory LOOPBACK_URL] [--observatory-max-age SECONDS]");
            return 0;
        default: return 2;
        }
    }
    if (optind != argc || (metrics && !valid_observatory_url(metrics))) {
        fputs("invalid arguments or non-local Observatory URL\n", stderr);
        return 2;
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return 1;
    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    signal(SIGPIPE, SIG_IGN);

    struct inventory current = {0};
    long ttl = 2 * interval + 6 * timeout + 2;
    int trusted = 0, rc = 0;
    if (publish(output, &current, "starting", NULL, ttl, route_ttl)) rc = 1;
    while (!stopping && !rc) {
        struct inventory next = {0};
        char err[160] = {0};
        int backlog = 0;
        long wait = interval;
        if (load_inventory(api, token, timeout * 1000, &next, err, sizeof(err)) != 0)
            goto unavailable;
        replace_inventory(&current, &next, trusted);
        trusted = 1;
        if (publish(output, &current, current.running ? "ok" : "stopped", NULL, ttl, route_ttl)) {
            rc = 1;
            break;
        }
        if (current.running) {
            struct member *jobs[16];
            size_t count = pick_jobs(&current, jobs, (size_t)workers, interval, &backlog);
            probe_members(jobs, count, timeout * 1000, mark);
            read_observatory(metrics, &current, timeout * 1000, route_ttl);
            if (load_inventory(api, token, timeout * 1000, &next, err, sizeof(err)) != 0)
                goto unavailable;
            replace_inventory(&current, &next, 1);
            if (publish(output, &current, current.running ? "ok" : "stopped", NULL, ttl, route_ttl))
                rc = 1;
            if (backlog) wait = 1;
        }
        goto sleep_cycle;
unavailable:
        trusted = 0;
        if (publish(output, &current, "stale", err, ttl, route_ttl)) rc = 1;
sleep_cycle:
        free_inventory(&next);
        if (!rc && !stopping) sleep((unsigned)wait);
    }
    free_inventory(&current);
    curl_global_cleanup();
    return rc;
}
