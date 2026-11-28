#define _GNU_SOURCE
#include "helper.h"
#include "capability.h"
#include "core_watch.h"
#include "routing_document.h"
#include "routing_editor.h"
#include "routing_validate.h"
#include "utf8.h"
#include "v2raya_api.h"
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

/* Keep routing_context comfortably below the 1 MiB ubus message limit. */
enum { POSITIONS_LIMIT = 400, POSITION_LABEL_LIMIT = 2048 };

static void revision(const char *text, char digest[17])
{
    uint64_t hash = UINT64_C(14695981039346656037);
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        hash ^= *p;
        hash *= UINT64_C(1099511628211);
    }
    snprintf(digest, 17, "%016" PRIx64, hash);
}

static int builtin_outbound(const char *name)
{
    return !strcmp(name, "direct") || !strcmp(name, "block");
}

static int outbound_ready(const struct inventory *inv, const char *name)
{
    if (builtin_outbound(name)) return 1;
    for (size_t i = 0; i < inv->count; i++)
        if (!strcmp(inv->outbounds[i].name, name))
            return inv->outbounds[i].count != 0;
    return 0;
}

static int restart_available(const struct v2raya_api *api, json_object *version)
{
#if LIBCURL_VERSION_NUM >= 0x075000
    char reason[160];
    return api->token_file && core_watch_local_api(api->base) &&
        capability_decide(version, FEATURE_CORE_START, reason, sizeof(reason)) == CAPABILITY_VERIFIED;
#else
    (void)api;
    (void)version;
    return 0;
#endif
}

static int running_core(const struct v2raya_api *api, char *error, size_t len)
{
    json_object *touch = v2raya_api_touch_data(api, error, len);
    if (!touch) return -1;
    json_object *running = json_object_object_get(touch, "running");
    int state = json_object_is_type(running, json_type_boolean) ? json_object_get_boolean(running) : -1;
    json_object_put(touch);
    if (state < 0) snprintf(error, len, "Cannot read the Xray running state");
    return state;
}

static const char *restart_xray(struct v2raya_api api, char *error, size_t len)
{
    if (!core_watch_local_api(api.base) || !api.token_file)
        return "Restart requires the router's local v2rayA API and authorization";
    volatile sig_atomic_t stopping = 0;
    struct core_watch_peer peer = {.api = api.base, .stopping = &stopping};
    api.connected_peer = core_watch_verify_peer;
    api.peer_context = &peer;
    json_object *version = v2raya_api_version_data(&api, error, len);
    if (!version) return *error ? error : "Cannot verify the local v2rayA process";
    int supported = restart_available(&api, version);
    json_object_put(version);
    if (!supported) return "Restart is not verified for this local v2rayA and core";

    int running = running_core(&api, error, len);
    if (running < 0) return error;
    if (!running) return "Xray is stopped";
    /* On verified v2rayA versions, a single POST rebuilds the core config and
     * restarts the running core under v2rayA's own update lock. */
    struct v2raya_api restart_api = api;
    restart_api.timeout_ms = 12000;
    if (v2raya_api_start_core(&restart_api, core_watch_verify_peer, &peer, error, len) ||
        running_core(&api, error, len) != 1)
        return "Could not confirm the Xray restart. Check its status before retrying.";
    return NULL;
}

static void add_outbound(json_object *rows, const char *name, int available)
{
    json_object *row = json_object_new_object();
    json_object_object_add(row, "name", json_object_new_string(name));
    json_object_object_add(row, "available", json_object_new_boolean(available));
    json_object_array_add(rows, row);
}

static json_object *position_label(const struct routing_position *position)
{
    const char *text = position->text;
    size_t length = position->length;
    if (!valid_utf8(text, length)) return json_object_new_string("");
    if (length <= POSITION_LABEL_LIMIT) return json_object_new_string_len(text, (int)length);

    static const char omitted[] = " … ";
    size_t start_length = POSITION_LABEL_LIMIT * 3 / 4;
    size_t end_start = length - (POSITION_LABEL_LIMIT - start_length - (sizeof(omitted) - 1));
    while (((unsigned char)text[start_length] & 0xc0) == 0x80) --start_length;
    while (((unsigned char)text[end_start] & 0xc0) == 0x80) ++end_start;

    char label[POSITION_LABEL_LIMIT];
    size_t end_label = start_length + sizeof(omitted) - 1;
    memcpy(label, text, start_length);
    memcpy(label + start_length, omitted, sizeof(omitted) - 1);
    memcpy(label + end_label, text + end_start, length - end_start);
    return json_object_new_string_len(label, (int)(end_label + length - end_start));
}

static void show_context(json_object *reply, const struct inventory *inv, const char *version,
                         enum capability save, const char *document, const char *digest, int advanced,
                         int can_restart)
{
    json_object *outbounds = json_object_new_array(), *positions = json_object_new_array();
    json_object_object_add(reply, "outbounds", outbounds);
    json_object_object_add(reply, "positions", positions);
    json_object_object_add(reply, "revision", json_object_new_string(digest));
    json_object_object_add(reply, "version", json_object_new_string(version));
    json_object_object_add(reply, "can_save", json_object_new_boolean(save != CAPABILITY_DENIED));
    json_object_object_add(reply, "can_restart", json_object_new_boolean(can_restart && inv->running));
    /* Outside the verified builds a save may make v2rayA restart its core. */
    json_object_object_add(reply, "save_verified", json_object_new_boolean(save == CAPABILITY_VERIFIED));
    json_object_object_add(reply, "validate_advanced", json_object_new_boolean(advanced));
    for (size_t i = 0; i < inv->count; i++) {
        const struct outbound *out = &inv->outbounds[i];
        if (!builtin_outbound(out->name)) add_outbound(outbounds, out->name, out->count != 0);
    }
    add_outbound(outbounds, "direct", 1);
    add_outbound(outbounds, "block", 1);
    /* Positions refer to the exact version of the document used for the preview.
     * Only proper routing rules are shown here; definitions may contain credentials. */
    struct routing_position available[POSITIONS_LIMIT];
    size_t count = routing_list_positions(document, available, POSITIONS_LIMIT);
    json_object_object_add(reply, "positions_total", json_object_new_int64((int64_t)count));
    for (size_t i = 0; i < count && i < POSITIONS_LIMIT; i++) {
        json_object *row = json_object_new_object();
        json_object_object_add(row, "line", json_object_new_int64((int64_t)available[i].line));
        json_object_object_add(row, "label", position_label(&available[i]));
        json_object_array_add(positions, row);
    }
}

int routing_editor_command(int argc, char **argv)
{
    if (argc != 4 && argc != 6) return 2;
    const int context = !strcmp(argv[0], "context"), save = !strcmp(argv[0], "save");
    const int restart = !strcmp(argv[0], "restart");
    if (!context && !save && !restart && strcmp(argv[0], "preview")) return 2;
    struct v2raya_api api = {.base = argv[1], .token_file = *argv[2] ? argv[2] : NULL, .timeout_ms = 2000};
    struct inventory inv = {0};
    json_object *request = NULL, *reply = json_object_new_object();
    if (!reply) return 1;
    const char *failure = NULL;
    char error[160] = {0}, digest[17], *document = NULL, *rule = NULL, *updated = NULL;
    json_object *version_data = NULL, *version = NULL;
    int lock = -1, initialized = 0;
    if (!context && !(request = read_rpc_json())) {
        failure = "Invalid rule request";
        goto done;
    }
    if (restart) {
        json_object *confirmed = json_object_object_get(request, "confirm");
        if (!json_object_is_type(confirmed, json_type_boolean) || !json_object_get_boolean(confirmed)) {
            failure = "Confirm that active proxy connections will be interrupted";
            goto done;
        }
    }
    if (save || restart) {
        lock = open(argv[3], O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB) < 0) {
            failure = "RoutingA is busy or its lock is unavailable";
            goto done;
        }
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        failure = "Cannot initialize the HTTP client";
        goto done;
    }
    initialized = 1;
    if (restart) {
        failure = restart_xray(api, error, sizeof(error));
        goto done;
    }
    if (!(version_data = v2raya_api_version_data(&api, error, sizeof(error))) ||
        !json_object_object_get_ex(version_data, "version", &version) ||
        !json_object_is_type(version, json_type_string) ||
        !(document = v2raya_api_get_routing(&api, error, sizeof(error))) ||
        load_inventory(&api, NULL, &inv, error, sizeof(error))) {
        failure = *error ? error : "Cannot read RoutingA from v2rayA";
        goto done;
    }
    revision(document, digest);
    const struct core_kind *core = core_kind_of(json_object_get_string(json_object_object_get(version_data, "variant")));
    if (context) {
        char reason[160];
        show_context(reply, &inv, json_object_get_string(version),
                     capability_decide(version_data, FEATURE_ROUTING_SAVE, reason, sizeof(reason)),
                     document, digest, argc == 6 && core, restart_available(&api, version_data));
        goto done;
    }
    const char *base = rpc_string(request, "revision");
    if (!base || strcmp(base, digest)) {
        failure = "RoutingA changed. Reload the page and preview the rule again.";
        goto done;
    }
    const char *outbound = rpc_string(request, "outbound"), *kind = rpc_string(request, "kind");
    const char *value = rpc_string(request, "value");
    json_object *line = json_object_object_get(request, "before_line");
    int64_t before_line = json_object_is_type(line, json_type_int) ? json_object_get_int64(line) : -1;
    if (before_line < 0 || before_line > INT32_MAX || !kind || !value || !outbound || !outbound_ready(&inv, outbound)) {
        failure = "Choose a current outbound with a server and a valid insertion position";
        goto done;
    }
    failure = routing_build_rule(kind, value, outbound, &rule);
    if (!failure) failure = routing_insert_rule(document, rule, (size_t)before_line, &updated);
    if (failure) goto done;
    if (save && (!strcmp(kind, "regexp") || !strcmp(kind, "geosite") || !strcmp(kind, "geoip")) &&
        (argc != 6 || !routing_validate_advanced(kind, value, core, argv[4], argv[5]))) {
        failure = argc == 6 && core ? "The local core rejected this expression or address list" :
            "Saving this rule requires validation with the local core";
        goto done;
    }
    json_object_object_add(reply, "rule", json_object_new_string(rule));
    json_object_object_add(reply, "revision", json_object_new_string(digest));
    json_object_object_add(reply, "before_line", json_object_new_int64(before_line));
    if (save && v2raya_api_save_routing(&api, document, updated, error, sizeof(error)))
        failure = *error ? error : "Cannot save RoutingA";
done:
    json_object_object_add(reply, "ok", json_object_new_boolean(!failure));
    if (failure) json_object_object_add(reply, "error", json_object_new_string(failure));
    puts(json_object_to_json_string_ext(reply, JSON_C_TO_STRING_PLAIN));
    json_object_put(request);
    json_object_put(reply);
    free_inventory(&inv);
    json_object_put(version_data);
    free(document);
    free(rule);
    free(updated);
    if (initialized) curl_global_cleanup();
    if (lock >= 0) close(lock);
    return 0;
}
