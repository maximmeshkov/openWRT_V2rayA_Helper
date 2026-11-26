#include "helper.h"
#include "utf8.h"
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
    json_object *request = parse_utf8_json(buffer, n);
    if (!json_object_is_type(request, json_type_object)) {
        json_object_put(request);
        return NULL;
    }
    return request;
}
