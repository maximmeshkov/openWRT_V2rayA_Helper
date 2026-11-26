#define _GNU_SOURCE
#include "failover_monitor.h"
#include "failover_api.h"
#include "failover_policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void add_text(json_object *object, const char *key, const char *value)
{
    json_object_object_add(object, key, json_object_new_string(value));
}

static int outbound_exists(const struct inventory *inv, const char *name)
{
    for (size_t i = 0; i < inv->count; i++)
        if (!strcmp(inv->outbounds[i].name, name)) return 1;
    return 0;
}

static const char *store_policy(const char *path, const struct inventory *inv,
    const struct failover_catalogue *catalog, json_object *policy_entry, int can_switch)
{
    struct failover_policy policy;
    if (failover_policy_parse(policy_entry, &policy) ||
        (policy.mode != FAILOVER_OFF && (!inv || !outbound_exists(inv, policy.outbound))))
        return "Choose an outbound and valid switching settings";
    size_t count = json_object_array_length(policy.candidates);
    if (policy.mode != FAILOVER_OFF) {
        json_object *permission = json_object_object_get(policy_entry, "allow_restart");
        if (!json_object_is_type(permission, json_type_boolean) || !json_object_get_boolean(permission))
            return "Confirm permission to restart Xray when this policy switches servers";
        if (!can_switch) return "Automatic switching is unavailable for this v2rayA version or core";
        if (!count) return "Select at least one server eligible for switching";
        for (size_t i = 0; i < count; i++) {
            const char *key = json_object_get_string(json_object_array_get_idx(policy.candidates, i));
            if (!failover_catalogue_find(catalog, key))
                return "A selected server was removed or is ambiguous. Reload the list.";
        }
    }

    char *lock_path = NULL;
    if (asprintf(&lock_path, "%s.lock", path) < 0) return "Cannot prepare settings";
    int lock = failover_lock_settings(lock_path);
    free(lock_path);
    if (lock < 0) return "Switching settings are busy";
    json_object *settings = failover_settings_read(path);
    const char *failure = "Cannot save switching settings";
    if (settings) {
        const char *const fields[] = {"outbound", "mode", "candidates", "failures", "failure_method",
                                     "failure_window_minutes",
                                     "max_ms", "cooldown_seconds", "start", "end"};
        json_object *entry = json_object_new_object();
        json_object *entries = json_object_object_get(settings, "policies");
        size_t index = 0;
        for (; index < json_object_array_length(entries); index++)
            if (!strcmp(policy.outbound, rpc_string(json_object_array_get_idx(entries, index), "outbound")))
                break;
        for (size_t i = 0; i < sizeof(fields)/sizeof(fields[0]); i++) {
            json_object *value = json_object_object_get(policy_entry, fields[i]);
            if (value) json_object_object_add(entry, fields[i], json_object_get(value));
        }
        json_object_array_put_idx(entries, index, entry);
        if (!failover_settings_write(path, settings)) failure = NULL;
    }
    json_object_put(settings);
    close(lock);
    return failure;
}

static const char *show_failover(json_object *reply, const char *path,
    const struct inventory *inv, const struct failover_catalogue *catalog, const char *version,
    int can_switch)
{
    json_object *settings = failover_settings_read(path);
    if (!settings) return "Cannot read switching settings";
    json_object *outbounds = json_object_new_array(), *nodes = json_object_new_array();
    json_object_object_add(reply, "outbounds", outbounds);
    json_object_object_add(reply, "nodes", nodes);
    json_object *policies = json_object_object_get(settings, "policies");
    json_object_object_add(reply, "policies", json_object_get(policies));
    if (version) add_text(reply, "version", version);
    json_object_object_add(reply, "can_switch", json_object_new_boolean(can_switch));
    if (!inv) json_object_object_add(reply, "catalog_unavailable", json_object_new_boolean(1));
    for (size_t i = 0; inv && i < inv->count; i++) {
        const struct outbound *out = &inv->outbounds[i];
        json_object *entry = json_object_new_object();
        add_text(entry, "name", out->name);
        if (out->count == 1) add_text(entry, "current", out->members[0].name);
        json_object_array_add(outbounds, entry);
    }
    for (size_t i = 0; catalog && i < catalog->count; i++) {
        const struct failover_node *node = &catalog->nodes[i];
        json_object *entry = json_object_new_object();
        add_text(entry, "key", node->key);
        add_text(entry, "name", node->name);
        add_text(entry, "address", node->address);
        add_text(entry, "net", node->net);
        json_object_array_add(nodes, entry);
    }
    for (size_t i = 0; i < json_object_array_length(policies); i++) {
        const char *name = rpc_string(json_object_array_get_idx(policies, i), "outbound");
        if (name && (!inv || !outbound_exists(inv, name))) {
            json_object *entry = json_object_new_object();
            add_text(entry, "name", name);
            json_object_array_add(outbounds, entry);
        }
    }
    json_object_put(settings);
    return NULL;
}

int failover_command(int argc, char **argv)
{
    if (argc != 4) return 2;
    int save = !strcmp(argv[0], "save");
    if (!save && strcmp(argv[0], "context")) return 2;
    json_object *reply = json_object_new_object();
    if (!reply) return 1;
    struct v2raya_api api = {.base = argv[1], .token_file = *argv[2] ? argv[2] : NULL, .timeout_ms = 2000};
    struct inventory inventory = {0};
    struct failover_catalogue catalog = {0};
    char error[160] = {0}, *version = NULL;
    const char *failure = NULL;
    int initialized = 0;
    json_object *request = save ? read_rpc_json() : NULL;
    json_object *entry = json_object_object_get(request, "policy");
    const char *mode = rpc_string(entry, "mode");
    if (save && !request)
        failure = "Invalid policy request";
    else if (save && mode && !strcmp(mode, "off"))
        failure = store_policy(argv[3], NULL, NULL, entry, 0);
    else if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        failure = "Cannot initialize the HTTP client";
    else {
        initialized = 1;
        version = v2raya_api_get_version(&api, error, sizeof(error));
        if (!version || load_inventory(api.base, api.token_file, NULL, api.timeout_ms,
                                        &inventory, error, sizeof(error)) ||
            failover_catalogue_read(&api, &catalog, error, sizeof(error))) {
            failure = save ? (*error ? error : "Cannot read servers from v2rayA") :
                show_failover(reply, argv[3], NULL, NULL, version, 0);
        } else {
            int can_switch = failover_api_can_switch(&api, error, sizeof(error));
            failure = save ? store_policy(argv[3], &inventory, &catalog, entry, can_switch) :
                show_failover(reply, argv[3], &inventory, &catalog, version, can_switch);
        }
    }
    json_object_object_add(reply, "ok", json_object_new_boolean(!failure));
    if (failure) add_text(reply, "error", failure);
    puts(json_object_to_json_string_ext(reply, JSON_C_TO_STRING_PLAIN));
    json_object_put(reply);
    json_object_put(request);
    failover_catalogue_free(&catalog);
    free_inventory(&inventory);
    free(version);
    if (initialized) curl_global_cleanup();
    return 0;
}
