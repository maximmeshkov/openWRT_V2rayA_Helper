#include "routing_document.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG_LIMIT 255
#define HOST_LIMIT 253
#define PATTERN_LIMIT 512

static int ascii_letter(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static int ascii_digit(unsigned char c)
{
    return c >= '0' && c <= '9';
}

static int identifier(const char *start, const char *end)
{
    if (start == end || end - start > TAG_LIMIT || (!ascii_letter(*start) && *start != '_'))
        return 0;
    for (const char *p = start + 1; p < end; ++p)
        if (!ascii_letter(*p) && !ascii_digit(*p) && *p != '_') return 0;
    return 1;
}

static int domain_value(const char *value, char out[HOST_LIMIT + 1], int contains)
{
    size_t length = strlen(value);
    if (!contains && length && value[length - 1] == '.') --length;
    if (!length || length > HOST_LIMIT) return 0;
    size_t label_length = 0;
    for (size_t i = 0; i < length; ++i) {
        const unsigned char c = value[i];
        if (!ascii_letter(c) && !ascii_digit(c) && c != '-' && c != '.' && !(contains && c == '_'))
            return 0;
        out[i] = c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
        if (contains) continue;
        if (c == '.') {
            if (!label_length || value[i - 1] == '-') return 0;
            label_length = 0;
        } else if ((!label_length && c == '-') || ++label_length > 63) {
            return 0;
        }
    }
    if (!contains && (!label_length || value[length - 1] == '-')) return 0;
    out[length] = '\0';
    return 1;
}

/* Return the address family so IPv6 can be quoted before the colon tokens
 * reach the grammar for named parameters. */
static int ip_family(const char *value)
{
    size_t length = strcspn(value, "/");
    char addr[INET6_ADDRSTRLEN];
    unsigned char bytes[16];
    if (!length || length >= sizeof(addr)) return 0;
    memcpy(addr, value, length);
    addr[length] = '\0';
    int family = AF_INET;
    unsigned max_prefix = 32;
    if (inet_pton(family, addr, bytes) != 1) {
        family = AF_INET6;
        max_prefix = 128;
        if (inet_pton(family, addr, bytes) != 1) return 0;
    }
    if (value[length] == '/') {
        const char *p = value + length + 1;
        if (!*p || strlen(p) > 3) return 0;
        unsigned prefix = 0;
        for (; *p; ++p) {
            if (!ascii_digit(*p)) return 0;
            prefix = prefix * 10 + (unsigned)(*p - '0');
        }
        if (prefix > max_prefix) return 0;
    }
    return family;
}

static int geo_value(const char *value, int geosite)
{
    if (!*value || strlen(value) > HOST_LIMIT) return 0;
    const char *p = value;
    if (!geosite && *p == '!') ++p;
    for (;;) {
        if (!ascii_letter(*p) && !ascii_digit(*p)) return 0;
        ++p;
        while (ascii_letter(*p) || ascii_digit(*p) || *p == '_' || *p == '-') ++p;
        if (!*p) return 1;
        if (!geosite || *p != '@') return 0;
        ++p;
    }
}

/* RoutingA strips quote wrappers without processing escapes. Quote the whole
 * value with the unused delimiter and reject the v2rayA $$...$$ macro marker. */
static const char *regexp_quote(const char *value)
{
    if (!*value || strlen(value) > PATTERN_LIMIT || strstr(value, "$$")) return NULL;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p)
        if (*p < 32 || *p >= 127) return NULL;
    if (!strchr(value, '"')) return "\"";
    if (!strchr(value, '\'')) return "'";
    return NULL;
}

const char *routing_build_rule(const char *type, const char *value, const char *outbound,
                               char **rule)
{
    if (!rule) return "invalid_rule";
    *rule = NULL;
    if (!type || !value || !outbound) return "invalid_rule";
    if (!identifier(outbound, outbound + strlen(outbound))) return "invalid_outbound_name";

    const char *function = "domain", *parameter = type, *separator = ": ", *quote = "";
    char normalized[HOST_LIMIT + 1];
    int contains = !strcmp(type, "contains");
    if (contains || !strcmp(type, "domain") || !strcmp(type, "full")) {
        if (!domain_value(value, normalized, contains)) return "invalid_domain";
        value = normalized;
    } else if (!strcmp(type, "ip")) {
        int family = ip_family(value);
        if (!family) return "invalid_ip_or_cidr";
        function = "ip";
        parameter = separator = "";
        if (family == AF_INET6) quote = "\"";
    } else if (!strcmp(type, "geosite") || !strcmp(type, "geoip")) {
        int geosite = !strcmp(type, "geosite");
        if (!geo_value(value, geosite)) return "invalid_geo_list";
        if (!geosite) function = "ip";
    } else if (!strcmp(type, "regexp")) {
        quote = regexp_quote(value);
        if (!quote) return "invalid_regexp_literal";
    } else {
        return "invalid_match_type";
    }

    size_t size = strlen(function) + strlen(parameter) + strlen(separator) + 2 * strlen(quote)
        + strlen(value) + strlen(outbound) + sizeof("() -> ");
    char *result = malloc(size);
    if (!result) return "out_of_memory";
    snprintf(result, size, "%s(%s%s%s%s%s) -> %s", function, parameter, separator,
             quote, value, quote, outbound);
    *rule = result;
    return NULL;
}

static const char *skip_space(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t')) ++p;
    return p;
}

static int routing_function(const char *p, size_t length)
{
    static const char *names[] = {"domain", "domains", "ip", "network", "port",
        "sourcePort", "protocol", "source", "user", "inboundTag"};
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); ++i)
        if (strlen(names[i]) == length && !memcmp(p, names[i], length)) return 1;
    return 0;
}

static const char *trim_line_end(const char *start, const char *end)
{
    if (start < end && end[-1] == '\r') --end;
    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) --end;
    return end;
}

/* Locate stand-alone routing statements without disclosing definitions. */
static int routing_line(const char *p, const char *end)
{
    end = trim_line_end(p, end);
    for (;;) {
        p = skip_space(p, end);
        const char *name = p;
        while (p < end && ascii_letter(*p)) ++p;
        if (!routing_function(name, p - name)) return 0;
        p = skip_space(p, end);
        if (p == end || *p++ != '(') return 0;
        while (p < end && *p != ')') {
            if (*p == '(') return 0;
            if (*p == '\'' || *p == '"') {
                char quote = *p++;
                p = memchr(p, quote, (size_t)(end - p));
                if (!p) return 0;
            }
            ++p;
        }
        if (p == end) return 0;
        p = skip_space(p + 1, end);
        if (end - p < 2) return 0;
        if (p[0] == '-' && p[1] == '>') return identifier(skip_space(p + 2, end), end);
        if (p[0] != '&' || p[1] != '&') return 0;
        p += 2;
    }
}

static const char *insert_point(const char *document, size_t line)
{
    if (!document || !line) return NULL;
    const char *start = document, *end;
    for (size_t current = 1; current < line; ++current) {
        end = strchr(start, '\n');
        if (!end) return NULL;
        start = end + 1;
    }
    end = strchr(start, '\n');
    if (!end) end = start + strlen(start);
    return routing_line(start, end) ? start : NULL;
}

int routing_can_insert_before(const char *document, size_t before_line)
{
    return insert_point(document, before_line) != NULL;
}

size_t routing_list_positions(const char *document, struct routing_position *positions, size_t capacity)
{
    size_t count = 0, line = 1;
    if (!document) return 0;
    for (const char *start = document; *start; ++line) {
        const char *end = strchr(start, '\n');
        const char *limit = end ? end : start + strlen(start);
        if (routing_line(start, limit)) {
            if (positions && count < capacity) {
                const char *text = skip_space(start, limit);
                positions[count] = (struct routing_position){
                    .line = line, .text = text, .length = (size_t)(trim_line_end(text, limit) - text)
                };
            }
            ++count;
        }
        if (!end) break;
        start = end + 1;
    }
    return count;
}

const char *routing_insert_rule(const char *document, const char *rule, size_t before_line,
                                char **updated)
{
    if (!updated) return "invalid_rule";
    *updated = NULL;
    if (!document || !rule || strpbrk(rule, "\r\n") || !routing_line(rule, rule + strlen(rule)))
        return "invalid_rule";
    size_t length = strlen(document), rule_length = strlen(rule);
    const char *point = before_line ? insert_point(document, before_line) : document + length;
    if (!point) return "invalid_insertion_point";
    const char *near = before_line ? strchr(point, '\n') : strrchr(document, '\n');
    if (!near && point > document && point[-1] == '\n') near = point - 1;
    int crlf = near && near > document && near[-1] == '\r';
    const char *newline = crlf ? "\r\n" : "\n";
    size_t newline_length = crlf ? 2 : 1;
    size_t leading = !before_line && length && document[length - 1] != '\n' ? newline_length : 0;
    size_t trailing = (before_line || !leading) ? newline_length : 0;
    if (SIZE_MAX - length <= rule_length || SIZE_MAX - length - rule_length <= leading + trailing)
        return "out_of_memory";
    char *result = malloc(length + rule_length + leading + trailing + 1);
    if (!result) return "out_of_memory";
    size_t prefix = (size_t)(point - document);
    memcpy(result, document, prefix);
    memcpy(result + prefix, newline, leading);
    memcpy(result + prefix + leading, rule, rule_length);
    memcpy(result + prefix + leading + rule_length, newline, trailing);
    memcpy(result + prefix + leading + rule_length + trailing, point, length - prefix + 1);
    *updated = result;
    return NULL;
}
