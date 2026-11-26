#define _POSIX_C_SOURCE 200809L
#include "lan_ingress.h"
#include <string.h>

enum { NFT_OUTPUT_LIMIT = 256 * 1024, REDIRECT_RULES = 6 };
enum chain_id { RULE_CHAIN, PRE_CHAIN, OUT_CHAIN, CHAIN_COUNT };

static const char *const chain_names[] = {"tp_rule", "tp_pre", "tp_out"};
static const char *const set_names[] = {"whitelist", "interface", "whitelist6", "interface6"};

struct chain {
    json_object *definition;
    json_object *rules[REDIRECT_RULES];
    size_t count;
};

static int string_is(json_object *value, const char *expected)
{
    return json_object_is_type(value, json_type_string) &&
           (size_t)json_object_get_string_len(value) == strlen(expected) &&
           !strcmp(json_object_get_string(value), expected);
}

static int field_is(json_object *object, const char *field, const char *expected)
{
    return string_is(json_object_object_get(object, field), expected);
}

static int integer_is(json_object *object, const char *field, int expected)
{
    json_object *value = json_object_object_get(object, field);
    return json_object_is_type(value, json_type_int) && json_object_get_int64(value) == expected;
}

static int fields(json_object *object, int required)
{
    json_object *handle;
    if (json_object_object_get_ex(object, "handle", &handle)) {
        if (!json_object_is_type(handle, json_type_int) || json_object_get_int64(handle) <= 0) return 0;
        ++required;
    }
    return json_object_object_length(object) == required;
}

static int matches(json_object *value, const char *expected)
{
    json_object *reference = json_tokener_parse(expected);
    int equal = reference && json_object_equal(value, reference);
    json_object_put(reference);
    return equal;
}

static int stock_set(json_object *set)
{
    for (size_t i = 0; i < sizeof(set_names) / sizeof(set_names[0]); ++i) {
        if (!field_is(set, "name", set_names[i])) continue;
        int required = 5;
        json_object *value;
        if (json_object_object_get_ex(set, "elem", &value)) {
            if (!json_object_is_type(value, json_type_array)) return 0;
            ++required;
        }
        if (json_object_object_get_ex(set, "auto-merge", &value)) {
            if (!json_object_is_type(value, json_type_boolean) || !json_object_get_boolean(value)) return 0;
            ++required;
        }
        if (fields(set, required) && field_is(set, "type", i < 2 ? "ipv4_addr" : "ipv6_addr") &&
            matches(json_object_object_get(set, "flags"), "[\"interval\"]")) return 1U << i;
        return 0;
    }
    return 0;
}

static int base_chain(json_object *definition, const char *hook)
{
    return definition && fields(definition, 7) && field_is(definition, "type", "nat") &&
           field_is(definition, "hook", hook) && integer_is(definition, "prio", -105) &&
           field_is(definition, "policy", "accept");
}

static int redirect_chain(const struct chain *chain)
{
    static const char *const rules[] = {
        "[{\"match\":{\"op\":\"==\",\"left\":{\"payload\":{\"protocol\":\"ip\",\"field\":\"daddr\"}},"
        "\"right\":\"@whitelist\"}},{\"return\":null}]",
        "[{\"match\":{\"op\":\"==\",\"left\":{\"payload\":{\"protocol\":\"ip\",\"field\":\"daddr\"}},"
        "\"right\":\"@interface\"}},{\"return\":null}]",
        "[{\"match\":{\"op\":\"==\",\"left\":{\"payload\":{\"protocol\":\"ip6\",\"field\":\"daddr\"}},"
        "\"right\":\"@whitelist6\"}},{\"return\":null}]",
        "[{\"match\":{\"op\":\"==\",\"left\":{\"payload\":{\"protocol\":\"ip6\",\"field\":\"daddr\"}},"
        "\"right\":\"@interface6\"}},{\"return\":null}]",
        "[{\"match\":{\"op\":\"==\",\"left\":{\"&\":[{\"meta\":{\"key\":\"mark\"}},128]},\"right\":128}},"
        "{\"return\":null}]",
        "[{\"match\":{\"op\":\"==\",\"left\":{\"meta\":{\"key\":\"l4proto\"}},\"right\":\"tcp\"}},"
        "{\"redirect\":{\"port\":52345}}]",
    };
    if (!chain->definition || !fields(chain->definition, 3) || chain->count != REDIRECT_RULES) return 0;
    for (size_t i = 0; i < REDIRECT_RULES; ++i)
        if (!matches(chain->rules[i], rules[i])) return 0;
    return 1;
}

static int jump_families(const struct chain *chain)
{
    if (chain->count != 1) return 0;
    json_object *expr = chain->rules[0];
    if (json_object_array_length(expr) != 3 ||
        !matches(json_object_array_get_idx(expr, 1),
                 "{\"match\":{\"op\":\"==\",\"left\":{\"meta\":{\"key\":\"l4proto\"}},\"right\":\"tcp\"}}") ||
        !matches(json_object_array_get_idx(expr, 2), "{\"jump\":{\"target\":\"tp_rule\"}}")) return 0;
    json_object *family = json_object_array_get_idx(expr, 0);
    if (matches(family,
                "{\"match\":{\"op\":\"==\",\"left\":{\"meta\":{\"key\":\"nfproto\"}},\"right\":\"ipv4\"}}")) return 1;
    return matches(family, "{\"match\":{\"op\":\"==\",\"left\":{\"meta\":{\"key\":\"nfproto\"}},"
                           "\"right\":{\"set\":[\"ipv4\",\"ipv6\"]}}}") ? 2 : 0;
}

static int add_identity_part(json_object *identity, json_object *part)
{
    if (!json_object_array_add(identity, json_object_get(part))) return 1;
    json_object_put(part);
    return 0;
}

static json_object *rules_identity(json_object *table, const struct chain *chains, json_object **sets)
{
    json_object *parts[] = {table, chains[RULE_CHAIN].definition, chains[PRE_CHAIN].definition,
                           chains[OUT_CHAIN].definition, sets[0], sets[1], sets[2], sets[3]};
    json_object *identity = json_object_new_array();
    if (!identity) return NULL;
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i) {
        json_object *handle = json_object_object_get(parts[i], "handle");
        if (!json_object_is_type(handle, json_type_int) || json_object_get_int64(handle) <= 0 ||
            !add_identity_part(identity, handle)) {
            json_object_put(identity);
            return NULL;
        }
    }
    /* Interface addresses are deliberately maintained by v2rayA during the core's lifetime. */
    json_object *v4 = json_object_object_get(sets[0], "elem");
    json_object *v6 = json_object_object_get(sets[2], "elem");
    if (!json_object_is_type(v4, json_type_array) || !json_object_array_length(v4) ||
        !json_object_is_type(v6, json_type_array) || !json_object_array_length(v6) ||
        !add_identity_part(identity, v4) || !add_identity_part(identity, v6)) {
        json_object_put(identity);
        return NULL;
    }
    return identity;
}

static json_object *nft_document(const char *output)
{
    size_t length = output ? strnlen(output, NFT_OUTPUT_LIMIT) : 0;
    if (!length || length == NFT_OUTPUT_LIMIT) return NULL;
    json_tokener *parser = json_tokener_new();
    if (!parser) return NULL;
    json_tokener_set_flags(parser, JSON_TOKENER_STRICT);
    json_object *root = json_tokener_parse_ex(parser, output, (int)length);
    int valid = json_tokener_get_error(parser) == json_tokener_success && json_tokener_get_parse_end(parser) == length;
    json_tokener_free(parser);
    if (valid && json_object_is_type(root, json_type_object) && json_object_object_length(root) == 1 &&
        json_object_is_type(json_object_object_get(root, "nftables"), json_type_array)) return root;
    json_object_put(root);
    return NULL;
}

enum lan_nft_table_state lan_ingress_nft_tables(const char *output)
{
    json_object *root = nft_document(output);
    if (!root) return LAN_NFT_UNKNOWN;
    json_object *entries = json_object_object_get(root, "nftables");
    int schema = 0, present = 0;
    enum lan_nft_table_state state = LAN_NFT_UNKNOWN;
    for (size_t i = 0; i < json_object_array_length(entries); ++i) {
        json_object *entry = json_object_array_get_idx(entries, i), *item;
        if (!json_object_is_type(entry, json_type_object) || json_object_object_length(entry) != 1) goto done;
        if (json_object_object_get_ex(entry, "metainfo", &item)) {
            if (schema || !integer_is(item, "json_schema_version", 1)) goto done;
            schema = 1;
            continue;
        }
        if (!json_object_object_get_ex(entry, "table", &item) || !field_is(item, "family", "inet")) goto done;
        json_object *name = json_object_object_get(item, "name");
        if (!json_object_is_type(name, json_type_string) || !json_object_get_string_len(name) ||
            strlen(json_object_get_string(name)) != (size_t)json_object_get_string_len(name)) goto done;
        if (string_is(name, "v2raya")) present = 1;
    }
    if (schema) state = present ? LAN_NFT_PRESENT : LAN_NFT_ABSENT;
done:
    json_object_put(root);
    return state;
}

struct lan_ingress lan_ingress_parse_nft(const char *output, json_object **identity)
{
    struct lan_ingress result = {0};
    if (identity) *identity = NULL;
    json_object *root = nft_document(output);
    if (!root) return result;
    json_object *entries = json_object_object_get(root, "nftables");

    struct chain chains[CHAIN_COUNT] = {0};
    int sets = 0, schema = 0;
    json_object *table = NULL, *set_definitions[4] = {0};
    for (size_t i = 0; i < json_object_array_length(entries); ++i) {
        json_object *entry = json_object_array_get_idx(entries, i), *item;
        if (!json_object_is_type(entry, json_type_object) || json_object_object_length(entry) != 1) goto done;
        if (json_object_object_get_ex(entry, "metainfo", &item)) {
            if (schema || !integer_is(item, "json_schema_version", 1)) goto done;
            schema = 1;
            continue;
        }
        if (json_object_object_get_ex(entry, "table", &item)) {
            if (table || !field_is(item, "family", "inet") || !field_is(item, "name", "v2raya")) goto done;
            table = item;
            result = (struct lan_ingress){.mode = "redirect", .backend = "nftables",
                                          .ipv4 = "unknown", .ipv6 = "unknown"};
            if (!fields(item, 2)) goto done;
            continue;
        }
        if (json_object_object_get_ex(entry, "set", &item)) {
            if (!field_is(item, "family", "inet") || !field_is(item, "table", "v2raya")) goto done;
            int bit = stock_set(item);
            if (!bit || (sets & bit)) goto done;
            set_definitions[__builtin_ctz((unsigned)bit)] = item;
            sets |= bit;
            continue;
        }
        int definition = json_object_object_get_ex(entry, "chain", &item);
        if ((!definition && !json_object_object_get_ex(entry, "rule", &item)) ||
            !field_is(item, "family", "inet") || !field_is(item, "table", "v2raya")) goto done;
        json_object *name = json_object_object_get(item, definition ? "name" : "chain");
        size_t index = 0;
        while (index < CHAIN_COUNT && !string_is(name, chain_names[index])) ++index;
        if (index == CHAIN_COUNT) goto done;
        struct chain *chain = &chains[index];
        if (definition) {
            if (chain->definition) goto done;
            chain->definition = item;
        } else {
            json_object *expr = json_object_object_get(item, "expr");
            if (chain->count == REDIRECT_RULES || !fields(item, 4) ||
                !json_object_is_type(expr, json_type_array)) goto done;
            chain->rules[chain->count++] = expr;
        }
    }

    if (!schema || !table || sets != 15 || !redirect_chain(&chains[RULE_CHAIN]) ||
        !base_chain(chains[OUT_CHAIN].definition, "output") ||
        !base_chain(chains[PRE_CHAIN].definition, "prerouting")) goto done;
    int expected = jump_families(&chains[OUT_CHAIN]);
    if (expected && (!chains[PRE_CHAIN].count || jump_families(&chains[PRE_CHAIN]) == expected)) {
        result.ipv4 = chains[PRE_CHAIN].count ? "attached" : "missing";
        if (expected == 2) result.ipv6 = result.ipv4;
        if (identity) *identity = rules_identity(table, chains, set_definitions);
    }
done:
    json_object_put(root);
    return result;
}
