#define _POSIX_C_SOURCE 200809L
#include "latency_history.h"
#include "utf8.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    HISTORY_SECONDS = 24 * 60 * 60,
    OUTBOUND_LIMIT = 64,
    TRACK_LIMIT = 512,
    ACTIVE_LIMIT = 1441,
    RESERVE_LIMIT = 256,
    SAMPLE_LIMIT = 16384,
    FILE_LIMIT = 2 * 1024 * 1024,
    NAME_LENGTH = 255,
    SERVER_LENGTH = 128,
    SERIES_LENGTH = 64,
};

enum result { RESULT_OK, RESULT_TIMEOUT, RESULT_ERROR };
static const char *const result_names[] = {"ok", "timeout", "error"};

struct track {
    struct track *next;
    char *server, *series;
    time_t newest;
    size_t refs, index;
    int reserve;
};

struct point {
    struct track *track;
    time_t at;
    int ms;
    enum result result;
};

struct outbound_history {
    char *name;
    struct track *tracks;
    struct point *points;
    size_t count, capacity, reserve_count;
};

struct latency_history {
    char *path;
    struct outbound_history outbounds[OUTBOUND_LIMIT];
    size_t count, sample_count, track_count;
    time_t next_expiry, now;
    int dirty;
};

static const char *string_value(json_object *value)
{
    if (!json_object_is_type(value, json_type_string)) return NULL;
    const char *s = json_object_get_string(value);
    return strlen(s) == (size_t)json_object_get_string_len(value) ? s : NULL;
}

static int valid_label(const char *text, size_t limit)
{
    if (!text || !*text) return 0;
    size_t length = strnlen(text, limit + 1);
    if (length > limit || !valid_utf8(text, length)) return 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++)
        if (*p < 32 || *p == 127) return 0;
    return 1;
}

static struct outbound_history *find_outbound(struct latency_history *h, const char *name)
{
    for (size_t i = 0; i < h->count; i++)
        if (!strcmp(h->outbounds[i].name, name)) return &h->outbounds[i];
    if (h->count == OUTBOUND_LIMIT) return NULL;
    char *copy = strdup(name);
    if (!copy) return NULL;
    struct outbound_history *out = &h->outbounds[h->count++];
    *out = (struct outbound_history){.name = copy};
    return out;
}

static void track_free(struct track *t)
{
    free(t->server);
    free(t->series);
    free(t);
}

static void forget_track(struct latency_history *h, struct outbound_history *out, struct track *t)
{
    struct track **p = &out->tracks;
    while (*p != t) p = &(*p)->next;
    *p = t->next;
    --h->track_count;
    track_free(t);
}

static void drop_point(struct latency_history *h, struct outbound_history *out, size_t i)
{
    struct track *track = out->points[i].track;
    if (track->reserve) --out->reserve_count;
    if (!--track->refs) forget_track(h, out, track);
    --out->count;
    --h->sample_count;
    memmove(out->points + i, out->points + i + 1, (out->count - i) * sizeof(*out->points));
    h->dirty = 1;
}

static void drop_oldest(struct latency_history *h)
{
    struct outbound_history *oldest = NULL;
    for (size_t i = 0; i < h->count; i++) {
        struct outbound_history *out = &h->outbounds[i];
        if (out->count && (!oldest || out->points[0].at < oldest->points[0].at))
            oldest = out;
    }
    if (oldest) drop_point(h, oldest, 0);
}

static struct track *find_track(struct outbound_history *out, const char *server,
                                const char *series, int reserve)
{
    for (struct track *t = out->tracks; t; t = t->next)
        if (t->reserve == reserve && !strcmp(t->series, series) && !strcmp(t->server, server))
            return t;
    return NULL;
}

static struct track *add_track(struct latency_history *h, struct outbound_history *out,
                               const char *server, const char *series, int reserve)
{
    struct track *t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->server = strdup(server);
    t->series = strdup(series);
    if (!t->server || !t->series) {
        track_free(t);
        return NULL;
    }
    t->reserve = reserve;
    t->next = out->tracks;
    out->tracks = t;
    ++h->track_count;
    return t;
}

static int make_room(struct outbound_history *out)
{
    if (out->count < out->capacity) return 1;
    size_t capacity = out->capacity ? out->capacity * 2 : 64;
    if (capacity > ACTIVE_LIMIT + RESERVE_LIMIT) capacity = ACTIVE_LIMIT + RESERVE_LIMIT;
    struct point *points = realloc(out->points, capacity * sizeof(*points));
    if (!points) return 0;
    out->points = points;
    out->capacity = capacity;
    return 1;
}

static void append_point(struct latency_history *h, const char *outbound, const char *server,
                         const char *series, time_t at, int ms, enum result result, int reserve)
{
    struct outbound_history *out = find_outbound(h, outbound);
    if (!out) return;
    struct track *t = find_track(out, server, series, reserve);
    if (t && at <= t->newest) return;

    size_t same_role = reserve ? out->reserve_count : out->count - out->reserve_count;
    if (same_role >= (size_t)(reserve ? RESERVE_LIMIT : ACTIVE_LIMIT)) {
        for (size_t i = 0; i < out->count; i++) {
            if (out->points[i].track->reserve == reserve) {
                drop_point(h, out, i);
                break;
            }
        }
    }
    if (h->sample_count >= SAMPLE_LIMIT) drop_oldest(h);
    if (!make_room(out)) return;
    t = find_track(out, server, series, reserve);
    if (!t) {
        while (h->track_count >= TRACK_LIMIT) drop_oldest(h);
        t = add_track(h, out, server, series, reserve);
    }
    if (!t) return;
    t->newest = at;
    ++t->refs;
    if (reserve) ++out->reserve_count;
    out->points[out->count++] = (struct point){.track=t, .at=at, .ms=ms, .result=result};
    ++h->sample_count;
    if (!h->next_expiry || at + HISTORY_SECONDS < h->next_expiry)
        h->next_expiry = at + HISTORY_SECONDS;
    h->dirty = 1;
}

void latency_history_add(struct latency_history *h, const char *outbound, const char *server,
                         const char *series, const struct measurement *sample, const char *role)
{
    if (!h || !sample || !sample->state || sample->checked <= 0 || !role ||
        !valid_label(outbound, NAME_LENGTH) || !server || !*server ||
        !valid_label(series, SERIES_LENGTH))
        return;
    if (strcmp(role, "active") && strcmp(role, "reserve")) return;
    enum result result;
    if (!strcmp(sample->state, "ok")) result = RESULT_OK;
    else if (!strcmp(sample->state, "timeout") ||
        (!strcmp(sample->state, "error") && sample->detail && !strcmp(sample->detail, "https_timeout")))
        result = RESULT_TIMEOUT;
    else if (!strcmp(sample->state, "error") || !strcmp(sample->state, "failed")) result = RESULT_ERROR;
    else return;
    if (result == RESULT_OK && (sample->ms < 0 || sample->ms > 60000)) return;

    /* Bound the RPC label without splitting a UTF-8 character. */
    size_t n = strnlen(server, SERVER_LENGTH);
    while (n && ((unsigned char)server[n] & 0xc0) == 0x80) --n;
    char label[SERVER_LENGTH + 1];
    memcpy(label, server, n);
    label[n] = '\0';
    if (!valid_label(label, SERVER_LENGTH)) return;
    append_point(h, outbound, label, series, sample->checked,
                 result == RESULT_OK ? (int)sample->ms : 0, result, !strcmp(role, "reserve"));
}

static int fresh(time_t at, time_t now)
{
    return at > 0 && now >= at && difftime(now, at) < HISTORY_SECONDS;
}

static void prune(struct latency_history *h, time_t now)
{
    if (h->next_expiry && now < h->next_expiry && now >= h->now) return;
    h->next_expiry = 0;
    for (size_t i = 0; i < h->count;) {
        struct outbound_history *out = &h->outbounds[i];
        for (struct track *track = out->tracks; track; track = track->next)
            track->newest = 0;
        size_t kept = 0;
        for (size_t n = 0; n < out->count; n++) {
            struct point item = out->points[n];
            if (!fresh(item.at, now)) {
                if (item.track->reserve) --out->reserve_count;
                if (!--item.track->refs) forget_track(h, out, item.track);
                --h->sample_count;
                h->dirty = 1;
            } else {
                if (item.at > item.track->newest) item.track->newest = item.at;
                if (!h->next_expiry || item.at + HISTORY_SECONDS < h->next_expiry)
                    h->next_expiry = item.at + HISTORY_SECONDS;
                out->points[kept++] = item;
            }
        }
        out->count = kept;
        if (out->count) {
            ++i;
            continue;
        }
        free(out->points);
        free(out->name);
        memmove(out, out + 1, (--h->count - i) * sizeof(*out));
    }
}

static json_object *encode_group(struct outbound_history *out)
{
    json_object *doc = json_object_new_object();
    json_object *tracks = json_object_new_array(), *points = json_object_new_array();
    json_object_object_add(doc, "name", json_object_new_string(out->name));
    json_object_object_add(doc, "tracks", tracks);
    json_object_object_add(doc, "points", points);
    size_t index = 0;
    for (struct track *t = out->tracks; t; t = t->next) {
        t->index = index++;
        json_object *entry = json_object_new_array_ext(3);
        json_object_array_add(entry, json_object_new_string(t->server));
        json_object_array_add(entry, json_object_new_string(t->series));
        json_object_array_add(entry, json_object_new_int(t->reserve));
        json_object_array_add(tracks, entry);
    }
    for (size_t i = 0; i < out->count; i++) {
        struct point p = out->points[i];
        json_object *entry = json_object_new_array_ext(4);
        json_object_array_add(entry, json_object_new_int64((int64_t)p.at));
        json_object_array_add(entry, json_object_new_int((int)p.track->index));
        json_object_array_add(entry, json_object_new_int(p.result));
        if (p.result == RESULT_OK) json_object_array_add(entry, json_object_new_int(p.ms));
        json_object_array_add(points, entry);
    }
    return doc;
}

static int write_history(struct latency_history *h, json_object *doc)
{
    size_t length = strlen(h->path) + sizeof(".XXXXXX");
    char *temp = malloc(length);
    if (!temp) return -1;
    snprintf(temp, length, "%s.XXXXXX", h->path);
    int fd = mkstemp(temp), rc = -1;
    if (fd >= 0) {
        int written = json_object_to_fd(fd, doc, JSON_C_TO_STRING_PLAIN);
        if (!close(fd) && !written) rc = rename(temp, h->path);
        if (rc) unlink(temp);
    }
    free(temp);
    return rc;
}

int latency_history_publish(struct latency_history *h, time_t now)
{
    if (!h || now <= 0) return 0;
    prune(h, now);
    h->now = now;
    if (!h->dirty) return 0;
    json_object *doc = json_object_new_array_ext((int)h->count);
    if (!doc) return -1;
    for (size_t i = 0; i < h->count; i++)
        if (h->outbounds[i].count) json_object_array_add(doc, encode_group(&h->outbounds[i]));
    int rc = write_history(h, doc);
    json_object_put(doc);
    if (!rc) h->dirty = 0;
    return rc;
}

static json_object *read_history(const char *path)
{
    if (!path) return NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return NULL;
    json_object *doc = NULL;
    char *data = NULL;
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > FILE_LIMIT)
        goto done;
    size_t size = (size_t)st.st_size, read_bytes = 0;
    data = malloc(size);
    if (!data) goto done;
    while (read_bytes < size) {
        ssize_t n = read(fd, data + read_bytes, size - read_bytes);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        read_bytes += (size_t)n;
    }
    doc = parse_utf8_json(data, size);
    if (!json_object_is_type(doc, json_type_array) || json_object_array_length(doc) > OUTBOUND_LIMIT) {
        json_object_put(doc);
        doc = NULL;
    }
done:
    close(fd);
    free(data);
    return doc;
}

static int read_point(json_object *item, json_object *tracks, time_t now, const char **server,
                      const char **series, struct point *p, int *reserve)
{
    if (!json_object_is_type(item, json_type_array) || !json_object_is_type(tracks, json_type_array))
        return 0;
    json_object *at = json_object_array_get_idx(item, 0), *index = json_object_array_get_idx(item, 1);
    json_object *result = json_object_array_get_idx(item, 2), *ms = json_object_array_get_idx(item, 3);
    if (!json_object_is_type(at, json_type_int) || !json_object_is_type(index, json_type_int) ||
        !json_object_is_type(result, json_type_int))
        return 0;
    int64_t when = json_object_get_int64(at), id = json_object_get_int64(index);
    if ((int64_t)(time_t)when != when || !fresh((time_t)when, now) ||
        id < 0 || (uint64_t)id >= json_object_array_length(tracks))
        return 0;
    json_object *track = json_object_array_get_idx(tracks, (size_t)id);
    if (!json_object_is_type(track, json_type_array) || json_object_array_length(track) != 3)
        return 0;
    *server = string_value(json_object_array_get_idx(track, 0));
    *series = string_value(json_object_array_get_idx(track, 1));
    json_object *role = json_object_array_get_idx(track, 2);
    int kind = json_object_get_int(result);
    if (!valid_label(*server, SERVER_LENGTH) || !valid_label(*series, SERIES_LENGTH) ||
        !json_object_is_type(role, json_type_int) ||
        (json_object_get_int(role) != 0 && json_object_get_int(role) != 1) ||
        kind < RESULT_OK || kind > RESULT_ERROR)
        return 0;
    *reserve = json_object_get_int(role);
    int64_t delay = json_object_get_int64(ms);
    if (kind == RESULT_OK && (!json_object_is_type(ms, json_type_int) || delay < 0 || delay > 60000))
        return 0;
    *p = (struct point){.at = (time_t)when, .result = kind, .ms = kind == RESULT_OK ? (int)delay : 0};
    return 1;
}

static json_object *group_points(json_object *group)
{
    json_object *points = json_object_object_get(group, "points");
    if (!json_object_is_type(points, json_type_array) ||
        json_object_array_length(points) > ACTIVE_LIMIT + RESERVE_LIMIT)
        return NULL;
    return points;
}

struct latency_history *latency_history_create(const char *path)
{
    if (!path || !*path) return NULL;
    struct latency_history *h = calloc(1, sizeof(*h));
    if (!h) return NULL;
    h->path = strdup(path);
    if (!h->path) {
        free(h);
        return NULL;
    }
    time_t now = time(NULL);
    json_object *doc = read_history(path);
    for (size_t i = 0; doc && i < json_object_array_length(doc); i++) {
        json_object *group = json_object_array_get_idx(doc, i);
        const char *name = string_value(json_object_object_get(group, "name"));
        json_object *tracks = json_object_object_get(group, "tracks"), *points = group_points(group);
        if (!valid_label(name, NAME_LENGTH) || !points) continue;
        for (size_t j = 0; j < json_object_array_length(points); j++) {
            const char *server, *series;
            struct point p;
            int reserve;
            if (read_point(json_object_array_get_idx(points, j), tracks, now, &server, &series, &p, &reserve))
                append_point(h, name, server, series, p.at, p.ms, p.result, reserve);
        }
    }
    /* On restart rewrite once, removing anything that expired while stopped. */
    h->dirty = 1;
    json_object_put(doc);
    return h;
}

void latency_history_free(struct latency_history *h)
{
    if (!h) return;
    for (size_t i = 0; i < h->count; i++) {
        struct outbound_history *out = &h->outbounds[i];
        while (out->tracks) {
            struct track *t = out->tracks;
            out->tracks = t->next;
            track_free(t);
        }
        free(out->points);
        free(out->name);
    }
    free(h->path);
    free(h);
}

static void rpc_point(json_object *samples, const char *server, const char *series,
                      const struct point *p, int reserve)
{
    json_object *item = json_object_new_object();
    json_object_object_add(item, "at", json_object_new_int64((int64_t)p->at));
    json_object_object_add(item, "role", json_object_new_string(reserve ? "reserve" : "active"));
    json_object_object_add(item, "server", json_object_new_string(server));
    json_object_object_add(item, "series", json_object_new_string(series));
    json_object_object_add(item, "state", json_object_new_string(result_names[p->result]));
    if (p->result == RESULT_OK) json_object_object_add(item, "ms", json_object_new_int(p->ms));
    json_object_array_add(samples, item);
}

static void rpc_histories(const char *path, json_object *reply, json_object *outbounds)
{
    struct latency_history *h = latency_history_create(path);
    json_object *groups = json_object_new_array();
    for (size_t i = 0; h && i < h->count; i++) {
        struct outbound_history *out = &h->outbounds[i];
        if (!out->count) continue;
        json_object_array_add(outbounds, json_object_new_string(out->name));
        json_object_array_add(groups, encode_group(out));
    }
    /* The compact JSON fits the 1 MiB ubus limit even at the history caps.
     * A blobmsg array would add headers to every timestamp, index and value. */
    const char *packed = json_object_to_json_string_ext(groups,
        JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
    json_object_object_add(reply, "histories", json_object_new_string(packed));
    json_object_put(groups);
    latency_history_free(h);
}

int latency_history_rpc(const char *path, const char *outbound)
{
    int combined = outbound && !*outbound;
    json_object *doc = combined ? NULL : read_history(path), *reply = json_object_new_object();
    json_object *outbounds = json_object_new_array(), *samples = json_object_new_array();
    time_t now = time(NULL);
    json_object_object_add(reply, "router_unix", json_object_new_int64((int64_t)now));
    json_object_object_add(reply, "outbounds", outbounds);
    json_object_object_add(reply, "samples", samples);
    if (combined) rpc_histories(path, reply, outbounds);
    int selected_added = 0;
    for (size_t i = 0; doc && i < json_object_array_length(doc); i++) {
        json_object *group = json_object_array_get_idx(doc, i);
        const char *name = string_value(json_object_object_get(group, "name"));
        json_object *tracks = json_object_object_get(group, "tracks"), *points = group_points(group);
        if (!valid_label(name, NAME_LENGTH) || !points) continue;
        int selected = !selected_added && outbound && !strcmp(outbound, name);
        int listed = 0;
        for (size_t j = 0; j < json_object_array_length(points); j++) {
            const char *server, *series;
            struct point p;
            int reserve;
            if (!read_point(json_object_array_get_idx(points, j), tracks, now, &server, &series, &p, &reserve))
                continue;
            if (!listed) {
                json_object_array_add(outbounds, json_object_new_string(name));
                listed = 1;
                if (!selected) break;
                selected_added = 1;
            }
            rpc_point(samples, server, series, &p, reserve);
        }
    }
    int rc = puts(json_object_to_json_string_ext(reply, JSON_C_TO_STRING_PLAIN)) < 0;
    json_object_put(reply);
    json_object_put(doc);
    return rc;
}
