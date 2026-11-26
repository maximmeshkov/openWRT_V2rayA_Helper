#ifndef V2RAYA_HELPER_UTF8_H
#define V2RAYA_HELPER_UTF8_H

#include <stddef.h>
#include <limits.h>
#include <json-c/json.h>

static inline int valid_utf8(const char *text, size_t length)
{
    const unsigned char *p = (const unsigned char *)text;
    for (size_t i = 0; i < length;) {
        unsigned first = p[i++];
        if (first < 128) continue;
        if (first < 0xc2 || first > 0xf4) return 0;
        unsigned more = first < 0xe0 ? 1 : first < 0xf0 ? 2 : 3;
        if (length - i < more) return 0;
        unsigned code = first & (0x7f >> (more + 1));
        for (unsigned n = 0; n < more; n++) {
            unsigned next = p[i++];
            if ((next & 0xc0) != 0x80) return 0;
            code = (code << 6) | (next & 0x3f);
        }
        if ((more == 2 && code < 0x800) || (more == 3 && code < 0x10000) ||
            (code >= 0xd800 && code <= 0xdfff) || code > 0x10ffff)
            return 0;
    }
    return 1;
}

/* Some json-c releases reject raw multibyte strings in strict mode. Check
 * UTF-8 and the complete input here; callers validate the object schema. */
static inline json_object *parse_utf8_json(const char *text, size_t length)
{
    if (!length || length > INT_MAX || !valid_utf8(text, length)) return NULL;
    json_tokener *tok = json_tokener_new();
    if (!tok) return NULL;
    json_object *value = json_tokener_parse_ex(tok, text, (int)length);
    size_t end = json_tokener_get_parse_end(tok);
    while (end < length && (text[end] == ' ' || text[end] == '\t' ||
                            text[end] == '\r' || text[end] == '\n'))
        ++end;
    if (end != length || json_tokener_get_error(tok) != json_tokener_success) {
        json_object_put(value);
        value = NULL;
    }
    json_tokener_free(tok);
    return value;
}

#endif
