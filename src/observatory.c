#include "helper.h"

#include <limits.h>
#include <string.h>

static int exact_tag(json_object *sample, const char *expected)
{
	json_object *tag = NULL;
	if (!json_object_object_get_ex(sample, "outbound_tag", &tag) || !json_object_is_type(tag, json_type_string))
		return 0;
	return (size_t)json_object_get_string_len(tag) == strlen(expected) &&
	       !strcmp(json_object_get_string(tag), expected);
}

static void apply_sample(struct outbound *out, json_object *sample, time_t now, long max_age)
{
	json_object *stamp = NULL, *alive = NULL, *delay = NULL, *reason = NULL;
	if (!json_object_is_type(sample, json_type_object) || !exact_tag(sample, out->name) ||
	    !json_object_object_get_ex(sample, "last_try_time", &stamp) || !json_object_is_type(stamp, json_type_int))
		return;
	int64_t t = json_object_get_int64(stamp);
	if (t <= 0 || t <= out->since || t > now || now - t > max_age)
		return;
	int has_alive = json_object_object_get_ex(sample, "alive", &alive);
	int has_delay = json_object_object_get_ex(sample, "delay", &delay);
	if ((has_alive && !json_object_is_type(alive, json_type_boolean)) ||
	    (has_delay && !json_object_is_type(delay, json_type_int)))
		return;
	int64_t ms = has_delay ? json_object_get_int64(delay) : 0;
	if (ms < 0 || ms > LONG_MAX)
		return;
	if (has_alive && json_object_get_boolean(alive)) {
		// Go's protobuf-generated JSON tags omit zero delay.
		out->route = (struct measurement){.state = "ok", .detail = "observatory_http", .ms = (long)ms, .checked = (time_t)t};
		return;
	}
	if (!has_alive) {
		// Xray 25.10.15 expvar also omits alive=false. Its failed HTTP
		// sample contains a sentinel delay AND a nonempty error reason.
		if (ms != 99999999 || !json_object_object_get_ex(sample, "last_error_reason", &reason) ||
		    !json_object_is_type(reason, json_type_string) || !json_object_get_string_len(reason))
			return;
	}
	out->route = (struct measurement){.state = "failed", .detail = "observatory_http", .checked = (time_t)t};
}

void read_observatory(const char *url, struct inventory *inv, long timeout_ms, long max_age)
{
	for (size_t i = 0; i < inv->count; i++)
		inv->outbounds[i].route = (struct measurement){.state = "unknown", .detail = "no_observation"};
	if (!inv->running || max_age <= 0 || !url || !*url || !valid_observatory_url(url))
		return;
	char error[128];
	json_object *root = fetch_json(url, NULL, timeout_ms, error, sizeof(error));
	json_object *observatory = NULL;
	if (json_object_object_get_ex(root, "observatory", &observatory) &&
	    json_object_is_type(observatory, json_type_object)) {
		time_t now = time(NULL);
		for (size_t i = 0; i < inv->count; i++) {
			struct outbound *out = &inv->outbounds[i];
			json_object *sample = NULL;
			// An exact logical tag with one member can be attributed. A
			// balancer may use distinct runtime tags for its group members.
			if (out->count == 1 && json_object_object_get_ex(observatory, out->name, &sample))
				apply_sample(out, sample, now, max_age);
		}
	}
	json_object_put(root);
}
