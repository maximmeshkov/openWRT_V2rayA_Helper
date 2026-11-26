#include "failover_api.h"
#include "node_key.h"
#include "utf8.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct catalogue_key {
    const char *key;
    size_t index;
};

static int compare_keys(const void *left, const void *right)
{
    const struct catalogue_key *a = left, *b = right;
    return strcmp(a->key, b->key);
}

static const struct catalogue_key *find_unique_key(const struct catalogue_key *keys,
                                                   size_t count, const char *key)
{
    if (!key || !count) return NULL;
    struct catalogue_key wanted = {.key = key};
    const struct catalogue_key *found = bsearch(&wanted, keys, count, sizeof(*keys), compare_keys);
    if (!found || (found > keys && !compare_keys(found - 1, found)) ||
        (found + 1 < keys + count && !compare_keys(found, found + 1)))
        return NULL;
    return found;
}

static const char *text(json_object *object, const char *field)
{
    json_object *value = json_object_object_get(object, field);
    if (!json_object_is_type(value, json_type_string)) return NULL;
    const char *s = json_object_get_string(value);
    return strlen(s) == (size_t)json_object_get_string_len(value) ? s : NULL;
}

static int64_t integer(json_object *object, const char *field)
{
    json_object *value = json_object_object_get(object, field);
    return json_object_is_type(value, json_type_int) ? json_object_get_int64(value) : -1;
}

static const char *subscription_name(json_object *subscription, const char *source)
{
    const char *remarks = text(subscription, "remarks");
    if (!remarks || !*remarks || strstr(remarks, source) || strstr(remarks, "://"))
        return NULL;
    size_t length = strnlen(remarks, 257);
    if (length > 256 || !valid_utf8(remarks, length) || strcspn(remarks, "\r\n\t") != length)
        return NULL;
    return remarks;
}

static int append_nodes(struct failover_catalogue *cat, json_object *servers, int64_t sub,
                        const char *subscription_key, size_t *capacity)
{
    if (!json_object_is_type(servers, json_type_array)) return 0;
    size_t n = json_object_array_length(servers);
    if (n > INT_MAX || n > SIZE_MAX - cat->count)
        return 0;
    size_t needed = cat->count + n;
    if (needed > *capacity) {
        size_t allocated = *capacity <= (SIZE_MAX / sizeof(*cat->nodes)) / 2 && *capacity * 2 > needed ?
                           *capacity * 2 : needed;
        if (allocated > SIZE_MAX / sizeof(*cat->nodes)) return 0;
        struct failover_node *nodes = realloc(cat->nodes, allocated * sizeof(*nodes));
        if (!nodes) return 0;
        *capacity = allocated;
        cat->nodes = nodes;
    }
    for (size_t i = 0; i < n; i++) {
        json_object *server = json_object_array_get_idx(servers, i);
        int64_t id = integer(server, "id");
        const char *type = text(server, "_type"), *name = text(server, "name");
        const char *address = text(server, "address"), *net = text(server, "net");
        if (id != (int64_t)i + 1 || !type || strcmp(type, sub < 0 ? "server" : "subscriptionServer") ||
            !name || !address || !*address || !net || !*net) return 0;
        struct failover_node *node = &cat->nodes[cat->count++];
        *node = (struct failover_node){.id=id, .sub=sub, .name=name, .address=address,
                                       .net=net, .subscription_key=subscription_key};
        node_key(node->key, type, subscription_key, name, address, net);
    }
    return 1;
}

/* Takes ownership of data on success and failure. */
static int parse_catalogue(json_object *data, struct failover_catalogue *cat, char *error, size_t len)
{
    *cat = (struct failover_catalogue){.data = data};
    if (!data) return -1;
    json_object *running = json_object_object_get(data, "running");
    json_object *touch = json_object_object_get(data, "touch");
    json_object *subs = json_object_object_get(touch, "subscriptions");
    json_object *refs = NULL, *paused = NULL;
    if (!json_object_is_type(running, json_type_boolean) || !json_object_is_type(subs, json_type_array) ||
        !json_object_object_get_ex(touch, "connectedServer", &refs) ||
        (refs && !json_object_is_type(refs, json_type_array)) ||
        (json_object_object_get_ex(data, "networkPaused", &paused) && !json_object_is_type(paused, json_type_boolean)))
        goto bad;
    cat->running = json_object_get_boolean(running) && !json_object_get_boolean(paused);
    size_t capacity = 0;
    if (!append_nodes(cat, json_object_object_get(touch, "servers"), -1, "", &capacity)) goto bad;
    size_t count = json_object_array_length(subs);
    if (count > INT_MAX) goto bad;
    cat->subscriptions = calloc(count, sizeof(*cat->subscriptions));
    cat->subscription_keys = calloc(count, sizeof(*cat->subscription_keys));
    if (count && (!cat->subscriptions || !cat->subscription_keys)) goto bad;
    cat->subscription_count = count;
    for (size_t i = 0; i < count; i++) {
        json_object *sub = json_object_array_get_idx(subs, i);
        const char *source = text(sub, "address"), *type = text(sub, "_type");
        json_object *servers = NULL;
        if (!source || !*source || !type || strcmp(type, "subscription") || integer(sub, "id") != (int64_t)i + 1 ||
            !json_object_object_get_ex(sub, "servers", &servers)) goto bad;
        struct failover_subscription *subscription = &cat->subscriptions[i];
        subscription->first = cat->count;
        if (servers && !append_nodes(cat, servers, (int64_t)i, source, &capacity)) goto bad;
        subscription->count = cat->count - subscription->first;
        subscription->name = subscription_name(sub, source);
        node_key(subscription->key, "subscription", source, "", "", "");
        cat->subscription_keys[i] = (struct catalogue_key){.key=subscription->key, .index=i};
    }
    cat->node_keys = calloc(cat->count, sizeof(*cat->node_keys));
    if (cat->count && !cat->node_keys) goto bad;
    for (size_t i = 0; i < cat->count; i++)
        cat->node_keys[i] = (struct catalogue_key){.key=cat->nodes[i].key, .index=i};
    if (cat->count > 1) qsort(cat->node_keys, cat->count, sizeof(*cat->node_keys), compare_keys);
    if (count > 1) qsort(cat->subscription_keys, count, sizeof(*cat->subscription_keys), compare_keys);
    return 0;
bad:
    failover_catalogue_free(cat);
    snprintf(error, len, "incomplete or inconsistent v2rayA server catalogue");
    return -1;
}

int failover_catalogue_read(const struct v2raya_api *api, struct failover_catalogue *cat, char *error, size_t len)
{
    return parse_catalogue(v2raya_api_touch_data(api, error, len), cat, error, len);
}

void failover_catalogue_free(struct failover_catalogue *cat)
{
    json_object_put(cat->data);
    free(cat->nodes);
    free(cat->subscriptions);
    free(cat->node_keys);
    free(cat->subscription_keys);
    *cat = (struct failover_catalogue){0};
}

const struct failover_node *failover_catalogue_find(const struct failover_catalogue *cat, const char *key)
{
    const struct catalogue_key *found = find_unique_key(cat->node_keys, cat->count, key);
    return found ? &cat->nodes[found->index] : NULL;
}

const struct failover_subscription *failover_catalogue_subscription(const struct failover_catalogue *cat,
                                                                   const char *key)
{
    const struct catalogue_key *found = find_unique_key(cat->subscription_keys, cat->subscription_count, key);
    return found ? &cat->subscriptions[found->index] : NULL;
}

const struct failover_node *failover_catalogue_active(const struct failover_catalogue *cat, const char *outbound)
{
    json_object *touch = json_object_object_get(cat->data, "touch");
    json_object *refs = json_object_object_get(touch, "connectedServer");
    const struct failover_node *active = NULL;
    if (!refs) return NULL;
    for (size_t i = 0; i < json_object_array_length(refs); i++) {
        json_object *ref = json_object_array_get_idx(refs, i);
        const char *out = text(ref, "outbound");
        if (!out) return NULL;
        if (strcmp(*out ? out : "proxy", outbound)) continue;
        const char *type = text(ref, "_type");
        int64_t id = integer(ref, "id"), sub;
        if (active || !type || id <= 0) return NULL;
        if (!strcmp(type, "server")) sub = -1;
        else if (!strcmp(type, "subscriptionServer") && (sub = integer(ref, "sub")) >= 0) {}
        else return NULL;
        for (size_t j = 0; j < cat->count; j++) {
            const struct failover_node *node = &cat->nodes[j];
            if (node->id == id && node->sub == sub) {
                active = node;
                break;
            }
        }
        if (!active) return NULL;
    }
    return active;
}

static json_object *which_for(const struct failover_node *node, const char *outbound)
{
    if (!node || node->id <= 0 || node->id > INT_MAX || node->sub < -1 || node->sub > INT_MAX)
        return NULL;
    json_object *which = json_object_new_object();
    if (!which) return NULL;
    json_object *type = json_object_new_string(node->sub < 0 ? "server" : "subscriptionServer");
    json_object *id = json_object_new_int64(node->id);
    json_object *sub = node->sub >= 0 ? json_object_new_int64(node->sub) : NULL;
    json_object *out = outbound ? json_object_new_string(outbound) : NULL;
    if (!type || !id || (node->sub >= 0 && !sub) || (outbound && !out)) {
        json_object_put(type);
        json_object_put(id);
        json_object_put(sub);
        json_object_put(out);
        json_object_put(which);
        return NULL;
    }
    json_object_object_add(which, "_type", type);
    json_object_object_add(which, "id", id);
    if (sub) json_object_object_add(which, "sub", sub);
    if (out) json_object_object_add(which, "outbound", out);
    return which;
}

char *failover_api_profile(const struct v2raya_api *api, const struct failover_node *node, char *error, size_t len)
{
    json_object *which = which_for(node, NULL);
    if (!which) {
        snprintf(error, len, "invalid server reference");
        return NULL;
    }
    char *profile = v2raya_api_export_node(api, which, error, len);
    json_object_put(which);
    return profile;
}

static int same_node(const struct failover_node *a, const struct failover_node *b)
{
    return a && b && (a->sub < 0) == (b->sub < 0) && !strcmp(a->key, b->key) &&
           !strcmp(a->name, b->name) && !strcmp(a->address, b->address) && !strcmp(a->net, b->net) &&
           !strcmp(a->subscription_key, b->subscription_key);
}

int failover_api_can_switch(const struct v2raya_api *api, char *error, size_t len)
{
    json_object *version_data = v2raya_api_version_data(api, error, len);
    if (!version_data) return 0;
    const char *version = text(version_data, "version"), *variant = text(version_data, "variant");
    int supported = version && !strcmp(version, "2.2.7.4") && variant && !strcmp(variant, "Xray");
    json_object_put(version_data);
    if (!supported)
        snprintf(error, len, "automatic connection changes require v2rayA 2.2.7.4 with Xray");
    return supported;
}

int failover_api_connect(const struct v2raya_api *api, const char *outbound,
                         const struct failover_node *expected_active, const struct failover_node *candidate,
                         const char *expected_profile, const char *expected_subscription,
                         int (*permitted)(void *), void *context,
                         char *error, size_t len)
{
    if (!outbound || !*outbound || !expected_active || !candidate || !expected_profile || !*expected_profile ||
        same_node(expected_active, candidate)) {
        snprintf(error, len, "invalid failover selection");
        return -1;
    }
    if (!failover_api_can_switch(api, error, len)) return -1;
    struct failover_catalogue cat, after;
    if (failover_catalogue_read(api, &cat, error, len)) return -1;
    const struct failover_node *active = failover_catalogue_active(&cat, outbound);
    const struct failover_node *next = failover_catalogue_find(&cat, candidate->key);
    int result = -1;
    if (!cat.running || !same_node(active, expected_active) || !same_node(next, candidate)) {
        snprintf(error, len, "v2rayA assignment or candidate changed before failover");
        goto done;
    }
    if (expected_subscription) {
        const struct failover_subscription *sub = failover_catalogue_subscription(&cat, expected_subscription);
        size_t index = (size_t)(next - cat.nodes);
        if (!sub || index < sub->first || index - sub->first >= sub->count) {
            snprintf(error, len, "selected subscription changed or became ambiguous before failover");
            goto done;
        }
    }
    char *profile = failover_api_profile(api, next, error, len);
    if (!profile) goto done;
    int matches = !strcmp(profile, expected_profile);
    free(profile);
    if (!matches) {
        snprintf(error, len, "verified candidate profile changed before failover");
        goto done;
    }
    json_object *which = which_for(next, outbound);
    if (!which) {
        snprintf(error, len, "invalid server reference");
        goto done;
    }
    struct v2raya_api connect_api = *api;
    if (connect_api.timeout_ms < 20000) connect_api.timeout_ms = 20000;
    json_object *reply = v2raya_api_connect_node(&connect_api, which, permitted, context, error, len);
    json_object_put(which);
    if (parse_catalogue(reply, &after, error, len)) goto done;
    if (after.running && same_node(failover_catalogue_active(&after, outbound), next))
        result = 0;
    else
        snprintf(error, len, "v2rayA did not confirm the changed assignment and a running core");
    failover_catalogue_free(&after);
done:
    failover_catalogue_free(&cat);
    return result;
}
