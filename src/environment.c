#define _GNU_SOURCE
#include "environment.h"
#include "capability.h"
#include "core_kind.h"
#include "core_watch.h"
#include "node_profile.h"
#include "v2raya_api.h"
#include <curl/curl.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *text(json_object *object, const char *key)
{
	json_object *value = json_object_object_get(object, key);
	return json_object_is_type(value, json_type_string) ? json_object_get_string(value) : NULL;
}

static void read_executable(pid_t pid, char *path, size_t size)
{
	static const char deleted[] = " (deleted)";
	char link[64];
	snprintf(link, sizeof(link), "/proc/%ld/exe", (long)pid);
	ssize_t length = readlink(link, path, size - 1);
	if (length <= 0 || (size_t)length == size - 1) length = 0;
	path[length] = '\0';
	size_t tail = sizeof(deleted) - 1;
	if ((size_t)length > tail && !strcmp(path + length - tail, deleted)) path[length - tail] = '\0';
}

static void read_environment_value(pid_t pid, const char *name, char *value, size_t size)
{
	char path[64], data[16384];
	snprintf(path, sizeof(path), "/proc/%ld/environ", (long)pid);
	*value = '\0';
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return;
	ssize_t length = read(fd, data, sizeof(data) - 1);
	close(fd);
	if (length <= 0) return;
	data[length] = '\0';
	size_t prefix = strlen(name);
	for (const char *item = data; item < data + length; item += strlen(item) + 1) {
		if (!strncmp(item, name, prefix) && item[prefix] == '=' && strlen(item + prefix + 1) < size) {
			strcpy(value, item + prefix + 1);
			return;
		}
	}
}

void environment_read_version(const char *api, struct environment *env)
{
	char error[160];
	const struct v2raya_api client = {.base = api, .timeout_ms = 2000};
	json_object_put(env->version_data);
	env->version_data = v2raya_api_version_data(&client, error, sizeof(error));
}

void environment_detect(const char *api, const char *config_path, struct environment *env)
{
	*env = (struct environment){0};
	environment_read_version(api, env);
	environment_find_core(api, config_path, env);
}

/* From /proc/<pid>/stat field 22 (start time in clock ticks) and /proc/uptime. */
static long process_age(pid_t pid)
{
	char path[64], data[1024];
	snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
	FILE *stat = fopen(path, "re"), *uptime = fopen("/proc/uptime", "re");
	size_t length = stat ? fread(data, 1, sizeof(data) - 1, stat) : 0;
	double up = -1;
	if (!uptime || fscanf(uptime, "%lf", &up) != 1) up = -1;
	if (stat) fclose(stat);
	if (uptime) fclose(uptime);
	data[length] = '\0';
	const char *field = strrchr(data, ')');
	unsigned long long started = 0;
	long ticks = sysconf(_SC_CLK_TCK);
	/* After the name: state is field 3, start time field 22. */
	for (int i = 3; field && i <= 22; i++) field = strchr(field + 1, ' ');
	if (!field || up < 0 || ticks <= 0 || sscanf(field, " %llu", &started) != 1) return -1;
	double age = up - (double)started / (double)ticks;
	return age < 0 ? 0 : (long)age;
}

void environment_find_core(const char *api, const char *config_path, struct environment *env)
{
	env->owner = env->core = 0;
	env->core_age = -1;
	env->owner_started = 0;
	*env->core_binary = *env->core_assets = '\0';
	json_object *config = node_config_read(config_path);
	struct core_watch_sample sample = {0};
	if (config) core_watch_sample(api, config_path, config, &sample);
	json_object_put(config);
	env->owner = sample.owner;
	env->owner_started = sample.owner_started;
	if (!sample.core) return;
	env->core = sample.core;
	env->core_age = process_age(sample.core);
	read_executable(sample.core, env->core_binary, sizeof(env->core_binary));
	const struct core_kind *kind = core_kind_of(text(env->version_data, "variant"));
	if (kind) {
		read_environment_value(sample.core, kind->asset_env, env->core_assets, sizeof(env->core_assets));
	} else {
		read_environment_value(sample.core, "XRAY_LOCATION_ASSET", env->core_assets, sizeof(env->core_assets));
		if (!*env->core_assets)
			read_environment_value(sample.core, "V2RAY_LOCATION_ASSET", env->core_assets, sizeof(env->core_assets));
	}
}

static json_object *feature_json(json_object *version_data, enum feature feature)
{
	char reason[160] = "";
	enum capability decision = capability_decide(version_data, feature, reason, sizeof(reason));
	static const char *const states[] = {
		[CAPABILITY_DENIED] = "denied", [CAPABILITY_VERIFIED] = "verified", [CAPABILITY_OPTED_IN] = "opted_in"};
	json_object *entry = json_object_new_object();
	json_object_object_add(entry, "state", json_object_new_string(states[decision]));
	if (decision == CAPABILITY_DENIED) json_object_object_add(entry, "reason", json_object_new_string(reason));
	return entry;
}

json_object *environment_to_json(const struct environment *env)
{
	json_object *doc = json_object_new_object();
	const char *version = text(env->version_data, "version"), *variant = text(env->version_data, "variant");
	if (version) json_object_object_add(doc, "version", json_object_new_string(version));
	if (variant) json_object_object_add(doc, "variant", json_object_new_string(variant));
	if (env->core) {
		json_object *core = json_object_new_object();
		json_object_object_add(core, "pid", json_object_new_int64(env->core));
		json_object_object_add(core, "binary", json_object_new_string(env->core_binary));
		json_object_object_add(core, "assets", json_object_new_string(env->core_assets));
		if (env->core_age >= 0) json_object_object_add(core, "age", json_object_new_int64(env->core_age));
		json_object_object_add(doc, "core", core);
	}
	if (env->version_data) {
		json_object *features = json_object_new_object();
		json_object_object_add(features, "switch", feature_json(env->version_data, FEATURE_SWITCH));
		json_object_object_add(features, "routing_save", feature_json(env->version_data, FEATURE_ROUTING_SAVE));
		json_object_object_add(features, "core_start", feature_json(env->version_data, FEATURE_CORE_START));
		json_object_object_add(features, "redirect_restore", feature_json(env->version_data, FEATURE_REDIRECT_RESTORE));
		json_object_object_add(doc, "features", features);
	}
	/* Core start, REDIRECT restore and login renewal check the accepting process (libcurl 7.80). */
	json_object_object_add(doc, "peer_check", json_object_new_boolean(LIBCURL_VERSION_NUM >= 0x075000));
	return doc;
}

void environment_free(struct environment *env)
{
	json_object_put(env->version_data);
	env->version_data = NULL;
}

int environment_command(int argc, char **argv)
{
	if (argc != 2) return 2;
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return 1;
	struct environment env;
	environment_detect(argv[0], argv[1], &env);
	json_object *doc = environment_to_json(&env);
	puts(json_object_to_json_string_ext(doc, JSON_C_TO_STRING_PLAIN));
	json_object_put(doc);
	environment_free(&env);
	curl_global_cleanup();
	return 0;
}
