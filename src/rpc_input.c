#include "helper.h"
#include <stdio.h>
#include <string.h>

const char *rpc_string(json_object *request, const char *key)
{
    json_object *item = json_object_object_get(request, key);
    if (!json_object_is_type(item, json_type_string)) return NULL;
    const char *value = json_object_get_string(item);
    return strlen(value) == (size_t)json_object_get_string_len(item) ? value : NULL;
}

json_object *read_rpc_json(void)
{
    char buffer[8192];
    size_t n = fread(buffer, 1, sizeof(buffer), stdin);
    if (!n || n == sizeof(buffer) || ferror(stdin)) return NULL;
    json_tokener *tok = json_tokener_new();
    if (!tok) return NULL;
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    json_object *request = json_tokener_parse_ex(tok, buffer, (int)n);
    json_tokener_free(tok);
    if (!json_object_is_type(request, json_type_object)) {
        json_object_put(request);
        return NULL;
    }
    return request;
}
