#define _POSIX_C_SOURCE 200809L
#include "lan_tproxy_nft.h"
#include <string.h>

enum { NFT_OUTPUT_LIMIT = 256 * 1024, MAX_CHAIN_RULES = 14 };
enum chain_id { PREROUTING, OUTPUT, TP_PRE, TP_OUT, TP_RULE, TP_MARK, CHAIN_COUNT };

static const char *const chain_name[] = {"prerouting", "output", "tp_pre", "tp_out", "tp_rule", "tp_mark"};
static const char *const set_name[] = {"interface", "interface6", "whitelist", "whitelist6"};

struct chain {
    json_object *definition;
    json_object *rules[MAX_CHAIN_RULES];
    size_t count;
};

#define META(key) "{\"meta\":{\"key\":\"" key "\"}}"
#define CT(key) "{\"ct\":{\"key\":\"" key "\"}}"
#define PAYLOAD(protocol, field) "{\"payload\":{\"protocol\":\"" protocol "\",\"field\":\"" field "\"}}"
#define FIB(flag) "{\"fib\":{\"result\":\"type\",\"flags\":[\"" flag "\"]}}"
#define MATCH(op, left, right) "{\"match\":{\"op\":\"" op "\",\"left\":" left ",\"right\":" right "}}"
#define MANGLE(key, value) "{\"mangle\":{\"key\":" key ",\"value\":" value "}}"
#define JUMP(target) "{\"jump\":{\"target\":\"" target "\"}}"
#define RETURN "{\"return\":null}"
#define TCP_OR_UDP MATCH("==", META("l4proto"), "{\"set\":[\"tcp\",\"udp\"]}")
#define MARK_MATCH(op, mask, value) MATCH(op, "{\"&\":[" META("mark") "," mask "]}", value)
#define SET_TPROXY_MARK MANGLE(META("mark"), "{\"|\":[" META("mark") ",64]}")
#define INTERFACE_RETURN(name) "[" MATCH("==", META("iifname"), "\"" name "\"") "," RETURN "]"
#define SET_RETURN(ip, name) "[" MATCH("==", PAYLOAD(ip, "daddr"), "\"@" name "\"") "," RETURN "]"

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
    if (!json_object_is_type(object, json_type_object)) return 0;
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

static int consume(const struct chain *chain, size_t *position, const char *rule)
{
    if (*position >= chain->count || !matches(chain->rules[*position], rule)) return 0;
    ++*position;
    return 1;
}

static int stock_set(json_object *set)
{
    for (size_t i = 0; i < sizeof(set_name) / sizeof(set_name[0]); ++i) {
        if (!field_is(set, "name", set_name[i])) continue;
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
        if (fields(set, required) && field_is(set, "type", i % 2 ? "ipv6_addr" : "ipv4_addr") &&
            matches(json_object_object_get(set, "flags"), "[\"interval\"]")) return 1U << i;
        return 0;
    }
    return 0;
}

static int base_chain(json_object *definition, const char *hook, const char *type)
{
    return fields(definition, 7) && field_is(definition, "type", type) &&
           field_is(definition, "hook", hook) && integer_is(definition, "prio", -155) &&
           field_is(definition, "policy", "accept");
}

static int stock_paths(const struct chain *chains, int whitelist)
{
    const struct chain *out = &chains[TP_OUT], *pre = &chains[TP_PRE];
    const struct chain *rule = &chains[TP_RULE], *mark = &chains[TP_MARK];
    if (out->count != 2 || pre->count != 4 || mark->count != 3) return 0;
    if (!matches(out->rules[0], "[" MARK_MATCH("==", "128", "128") "," RETURN "]") ||
        !matches(out->rules[1], "[" TCP_OR_UDP "," MATCH("==", FIB("saddr"), "\"local\"") ","
                 MATCH("!=", FIB("daddr"), "\"local\"") "," JUMP("tp_rule") "]") ||
        !matches(pre->rules[0], "[" MATCH("==", META("iifname"), "\"lo\"") ","
                 MARK_MATCH("!=", "192", "64") "," RETURN "]") ||
        !matches(pre->rules[1], "[" TCP_OR_UDP "," MATCH("!=", FIB("saddr"), "\"local\"") ","
                 MATCH("!=", FIB("daddr"), "\"local\"") "," JUMP("tp_rule") "]") ||
        !matches(pre->rules[2], "[" TCP_OR_UDP "," MARK_MATCH("==", "192", "64") ","
                 "{\"tproxy\":{\"family\":\"ip\",\"addr\":\"127.0.0.1\",\"port\":52345}}]") ||
        !matches(pre->rules[3], "[" TCP_OR_UDP "," MARK_MATCH("==", "192", "64") ","
                 "{\"tproxy\":{\"family\":\"ip6\",\"addr\":\"::1\",\"port\":52345}}]")) return 0;

    if (!matches(mark->rules[0], "[" MATCH("==", "{\"&\":[" PAYLOAD("tcp", "flags")
                 ",{\"|\":[\"fin\",\"syn\",\"rst\",\"ack\"]}]}", "\"syn\"") "," SET_TPROXY_MARK "]") ||
        !matches(mark->rules[1], "[" MATCH("==", META("l4proto"), "\"udp\"") ","
                 MATCH("in", CT("state"), "\"new\"") "," SET_TPROXY_MARK "]") ||
        !matches(mark->rules[2], "[" MANGLE(CT("mark"), META("mark")) "]")) return 0;

    size_t position = 0;
    const char *marked = "[" MARK_MATCH("==", "192", "64") "," RETURN "]";
    if (!consume(rule, &position, "[" MANGLE(META("mark"), CT("mark")) "]") ||
        !consume(rule, &position, marked)) return 0;
    /* The OpenWrt build can turn off the upstream bridge exception. */
    consume(rule, &position, INTERFACE_RETURN("br-*"));
    if (!consume(rule, &position, INTERFACE_RETURN("docker*")) ||
        !consume(rule, &position, INTERFACE_RETURN("veth*")) ||
        !consume(rule, &position, INTERFACE_RETURN("wg*")) ||
        !consume(rule, &position, INTERFACE_RETURN("ppp*"))) return 0;
    if (consume(rule, &position, "[" TCP_OR_UDP "," MATCH("==", PAYLOAD("th", "dport"), "53") ","
                JUMP("tp_mark") "]") && !consume(rule, &position, marked)) return 0;
    return consume(rule, &position, SET_RETURN("ip", "interface")) &&
           (!whitelist || (consume(rule, &position, SET_RETURN("ip", "whitelist")) &&
                           consume(rule, &position, SET_RETURN("ip6", "whitelist6")))) &&
           consume(rule, &position, SET_RETURN("ip6", "interface6")) &&
           consume(rule, &position, "[" JUMP("tp_mark") "]") && position == rule->count;
}

static int hook_families(const struct chain *chain, const char *target)
{
    if (chain->count != 1 || json_object_array_length(chain->rules[0]) != 2) return 0;
    json_object *rule = chain->rules[0];
    json_object *jump = json_object_array_get_idx(rule, 1);
    if (!json_object_is_type(jump, json_type_object) || json_object_object_length(jump) != 1) return 0;
    jump = json_object_object_get(jump, "jump");
    if (!json_object_is_type(jump, json_type_object) || json_object_object_length(jump) != 1 ||
        !field_is(jump, "target", target)) return 0;
    json_object *family = json_object_array_get_idx(rule, 0);
    if (matches(family, MATCH("==", META("nfproto"), "\"ipv4\""))) return 1;
    return matches(family, MATCH("==", META("nfproto"), "{\"set\":[\"ipv4\",\"ipv6\"]}")) ? 2 : 0;
}

struct lan_ingress lan_tproxy_parse_nft(const char *output)
{
    struct lan_ingress result = {0};
    size_t length = output ? strnlen(output, NFT_OUTPUT_LIMIT) : 0;
    if (!length || length == NFT_OUTPUT_LIMIT) return result;
    json_tokener *parser = json_tokener_new();
    if (!parser) return result;
    json_tokener_set_flags(parser, JSON_TOKENER_STRICT);
    json_object *root = json_tokener_parse_ex(parser, output, (int)length);
    int valid = json_tokener_get_error(parser) == json_tokener_success && json_tokener_get_parse_end(parser) == length;
    json_tokener_free(parser);
    json_object *entries = json_object_object_get(root, "nftables");
    if (!valid || !json_object_is_type(entries, json_type_array) || json_object_object_length(root) != 1) goto done;

    struct chain chains[CHAIN_COUNT] = {0};
    int schema = 0, table = 0, sets = 0;
    for (size_t i = 0; i < json_object_array_length(entries); ++i) {
        json_object *entry = json_object_array_get_idx(entries, i), *item;
        if (!json_object_is_type(entry, json_type_object) || json_object_object_length(entry) != 1) goto done;
        if (json_object_object_get_ex(entry, "metainfo", &item)) {
            if (schema || !integer_is(item, "json_schema_version", 1)) goto done;
            schema = 1;
            continue;
        }
        if (json_object_object_get_ex(entry, "table", &item)) {
            if (table || !fields(item, 2) || !field_is(item, "family", "inet") ||
                !field_is(item, "name", "v2raya")) goto done;
            table = 1;
            continue;
        }
        if (json_object_object_get_ex(entry, "set", &item)) {
            if (!field_is(item, "family", "inet") || !field_is(item, "table", "v2raya")) goto done;
            int bit = stock_set(item);
            if (!bit || (sets & bit)) goto done;
            sets |= bit;
            continue;
        }
        int definition = json_object_object_get_ex(entry, "chain", &item);
        if ((!definition && !json_object_object_get_ex(entry, "rule", &item)) ||
            !field_is(item, "family", "inet") || !field_is(item, "table", "v2raya")) goto done;
        json_object *name = json_object_object_get(item, definition ? "name" : "chain");
        size_t index = 0;
        while (index < CHAIN_COUNT && !string_is(name, chain_name[index])) ++index;
        if (index == CHAIN_COUNT) goto done;
        struct chain *chain = &chains[index];
        if (definition) {
            if (chain->definition) goto done;
            chain->definition = item;
        } else {
            json_object *expr = json_object_object_get(item, "expr");
            if (chain->count == MAX_CHAIN_RULES || !fields(item, 4) ||
                !json_object_is_type(expr, json_type_array)) goto done;
            chain->rules[chain->count++] = expr;
        }
    }

    if (!schema || !table || (sets != 3 && sets != 15) ||
        !base_chain(chains[OUTPUT].definition, "output", "route")) goto done;
    result = (struct lan_ingress){.backend = "nftables", .mode = "tproxy",
                                  .ipv4 = "unknown", .ipv6 = "unknown"};
    for (size_t i = TP_PRE; i < CHAIN_COUNT; ++i)
        if (!fields(chains[i].definition, 3)) goto done;

    int families = hook_families(&chains[OUTPUT], "tp_out");
    const struct chain *pre = &chains[PREROUTING];
    if (!families || !stock_paths(chains, sets == 15) ||
        (pre->definition && !base_chain(pre->definition, "prerouting", "filter")) ||
        (pre->count && (!pre->definition || hook_families(pre, "tp_pre") != families))) goto done;

    result.ipv4 = pre->count ? "attached" : "missing";
    result.ipv4_reason = pre->count ? NULL : "hook_missing";
    if (families == 2) {
        result.ipv6 = result.ipv4;
        result.ipv6_reason = result.ipv4_reason;
    }
done:
    json_object_put(root);
    return result;
}
