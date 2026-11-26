#include "redirect_checkpoint.h"
#include "boot_id.h"
#include "helper.h"
#include "private_state.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

enum { REDIRECT_STATE_LIMIT = 256 * 1024 };
static const char format[] = "VRAREDIRECT1";

struct redirect_checkpoint {
    struct private_state *state;
    json_object *scope;
};

static int append(json_object *array, json_object *value)
{
    if (value && !json_object_array_add(array, value)) return 1;
    json_object_put(value);
    return 0;
}

static json_object *namespace_scope(const char *path)
{
    struct stat ns = {0};
    if (stat(path, &ns) && errno != ENOENT) return NULL;
    json_object *pair = json_object_new_array();
    if (pair && append(pair, json_object_new_uint64(ns.st_dev)) &&
        append(pair, json_object_new_uint64(ns.st_ino))) return pair;
    json_object_put(pair);
    return NULL;
}

static json_object *current_scope(const char *api, const char *config)
{
    char boot[BOOT_ID_LENGTH + 1];
    if (!boot_id_read(boot)) return NULL;
    json_object *scope = json_object_new_array();
    if (scope && append(scope, json_object_new_string(boot)) &&
        append(scope, namespace_scope("/proc/self/ns/pid")) &&
        append(scope, namespace_scope("/proc/self/ns/net")) &&
        append(scope, namespace_scope("/proc/self/ns/mnt")) &&
        append(scope, namespace_scope("/proc/self/ns/time")) &&
        append(scope, json_object_new_string(api)) && append(scope, json_object_new_string(config)))
        return scope;
    json_object_put(scope);
    return NULL;
}

static int load(struct redirect_checkpoint *checkpoint, json_object **witness, int64_t *retry_at)
{
    char *data = malloc(REDIRECT_STATE_LIMIT);
    if (!data) return 0;
    size_t length = 0;
    int exists = private_state_read(checkpoint->state, data, REDIRECT_STATE_LIMIT, &length);
    if (exists <= 0) {
        free(data);
        return exists == 0;
    }
    json_tokener *parser = json_tokener_new();
    if (!parser) { free(data); return 0; }
    json_tokener_set_flags(parser, JSON_TOKENER_STRICT);
    json_object *record = json_tokener_parse_ex(parser, data, (int)length);
    int valid = json_tokener_get_error(parser) == json_tokener_success && json_tokener_get_parse_end(parser) == length;
    json_tokener_free(parser);
    free(data);
    if (!valid || !json_object_is_type(record, json_type_object)) { json_object_put(record); return 0; }

    json_object *type = json_object_object_get(record, "format");
    json_object *scope = json_object_object_get(record, "scope");
    json_object *retry = json_object_object_get(record, "retry_at"), *saved = NULL;
    valid = json_object_object_length(record) == 4 && json_object_is_type(type, json_type_string) &&
            json_object_get_string_len(type) == (int)sizeof(format) - 1 && !strcmp(json_object_get_string(type), format) &&
            json_object_is_type(scope, json_type_array) && json_object_is_type(retry, json_type_int) &&
            json_object_object_get_ex(record, "witness", &saved) && (!saved || json_object_is_type(saved, json_type_array));
    if (valid && json_object_equal(scope, checkpoint->scope)) {
        int64_t when = json_object_get_int64(retry);
        if (when < 0 || when > probe_clock_ms() + 60000) valid = 0;
        else {
            *retry_at = when;
            *witness = json_object_get(saved);
        }
    }
    json_object_put(record);
    return valid;
}

struct redirect_checkpoint *redirect_checkpoint_open(const char *path, const char *api, const char *config,
                                                     json_object **witness, int64_t *retry_at)
{
    struct redirect_checkpoint *checkpoint = calloc(1, sizeof(*checkpoint));
    if (!checkpoint) return NULL;
    checkpoint->scope = current_scope(api, config);
    if (checkpoint->scope) checkpoint->state = private_state_open(path);
    if (checkpoint->state && load(checkpoint, witness, retry_at)) return checkpoint;
    redirect_checkpoint_close(checkpoint);
    return NULL;
}

static int member(json_object *object, const char *name, json_object *value)
{
    if (!json_object_object_add(object, name, value)) return 1;
    json_object_put(value);
    return 0;
}

int redirect_checkpoint_save(struct redirect_checkpoint *checkpoint, json_object *witness, int64_t retry_at)
{
    if (!checkpoint) return 1;
    json_object *record = json_object_new_object();
    if (!record) return 0;
    int saved = 0;
    json_object *value = json_object_new_string(format);
    if (value && member(record, "format", value) &&
        member(record, "scope", json_object_get(checkpoint->scope)) &&
        (value = json_object_new_int64(retry_at)) && member(record, "retry_at", value) &&
        member(record, "witness", json_object_get(witness))) {
        size_t length;
        const char *data = json_object_to_json_string_length(record, JSON_C_TO_STRING_PLAIN, &length);
        saved = data && length <= REDIRECT_STATE_LIMIT && private_state_write(checkpoint->state, data, length);
    }
    json_object_put(record);
    return saved;
}

void redirect_checkpoint_close(struct redirect_checkpoint *checkpoint)
{
    if (!checkpoint) return;
    private_state_close(checkpoint->state);
    json_object_put(checkpoint->scope);
    free(checkpoint);
}
