#include "failover_api.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* SHA-256, FIPS 180-4. The public key is the first 128 bits of the digest. */
struct digest {
    uint32_t h[8];
    uint64_t bytes;
    unsigned char block[64];
};

static uint32_t rotate(uint32_t n, unsigned bits)
{
    return (n >> bits) | (n << (32 - bits));
}

static void digest_block(struct digest *d)
{
    static const uint32_t k[] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    uint32_t w[64];
    for (size_t i = 0; i < 16; i++) {
        const unsigned char *b = d->block + 4 * i;
        w[i] = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
    }
    for (size_t i = 16; i < 64; i++) {
        uint32_t a = w[i-15], b = w[i-2];
        uint32_t s0 = rotate(a, 7) ^ rotate(a, 18) ^ (a >> 3);
        uint32_t s1 = rotate(b, 17) ^ rotate(b, 19) ^ (b >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=d->h[0], b=d->h[1], c=d->h[2], t=d->h[3];
    uint32_t e=d->h[4], f=d->h[5], g=d->h[6], h=d->h[7];
    for (size_t i = 0; i < 64; i++) {
        uint32_t s1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
        uint32_t choose = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + choose + k[i] + w[i];
        uint32_t s0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        h=g; g=f; f=e; e=t+t1;
        t=c; c=b; b=a; a=t1+s0+majority;
    }
    d->h[0]+=a; d->h[1]+=b; d->h[2]+=c; d->h[3]+=t;
    d->h[4]+=e; d->h[5]+=f; d->h[6]+=g; d->h[7]+=h;
}

static void digest_update(struct digest *d, const void *bytes, size_t len)
{
    const unsigned char *p = bytes;
    while (len) {
        size_t i = d->bytes % sizeof(d->block);
        size_t n = sizeof(d->block) - i;
        if (n > len) n = len;
        memcpy(d->block + i, p, n);
        d->bytes += n;
        if (i + n == sizeof(d->block)) digest_block(d);
        p += n;
        len -= n;
    }
}

static void key_for(struct failover_node *node)
{
    struct digest d = {{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}, 0, {0}};
    const char *fields[] = { node->sub < 0 ? "server" : "subscriptionServer",
                             node->subscription_key, node->name, node->address, node->net };
    for (size_t i = 0; i < sizeof(fields)/sizeof(fields[0]); i++)
        digest_update(&d, fields[i], strlen(fields[i]) + 1);
    uint64_t bits = d.bytes * 8;
    unsigned char padding[64] = {0x80};
    size_t len = 1 + (119 - d.bytes % 64) % 64;
    digest_update(&d, padding, len);
    unsigned char trailer[8];
    for (size_t i = 0; i < 8; i++) trailer[i] = (unsigned char)(bits >> (56 - 8 * i));
    digest_update(&d, trailer, sizeof(trailer));
    for (size_t i = 0; i < 4; i++) snprintf(node->key + 8 * i, 9, "%08x", (unsigned int)d.h[i]);
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
        key_for(node);
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
    for (size_t i = 0; i < count; i++) {
        json_object *sub = json_object_array_get_idx(subs, i);
        const char *key = text(sub, "address"), *type = text(sub, "_type");
        if (!key || !*key || !type || strcmp(type, "subscription") || integer(sub, "id") != (int64_t)i + 1 ||
            !append_nodes(cat, json_object_object_get(sub, "servers"), (int64_t)i, key, &capacity)) goto bad;
    }
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
    *cat = (struct failover_catalogue){0};
}

const struct failover_node *failover_catalogue_find(const struct failover_catalogue *cat, const char *key)
{
    const struct failover_node *found = NULL;
    for (size_t i = 0; i < cat->count; i++) {
        const struct failover_node *node = &cat->nodes[i];
        if (strcmp(key, node->key)) continue;
        if (found) return NULL;
        found = node;
    }
    return found;
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
                         const char *expected_profile, int (*permitted)(void *), void *context,
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
