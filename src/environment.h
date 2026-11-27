#ifndef V2RAYA_HELPER_ENVIRONMENT_H
#define V2RAYA_HELPER_ENVIRONMENT_H

#include <json-c/json.h>
#include <limits.h>
#include <sys/types.h>

/* What this router runs: the v2rayA build and the core it started. */
struct environment {
	json_object *version_data;     /* GET /api/version; NULL when v2rayA did not answer */
	pid_t owner;                   /* the v2rayA process that owns the API, or 0 */
	unsigned long long owner_started;
	pid_t core;                    /* live core child of v2rayA, or 0 */
	long core_age;                 /* seconds since that process started, or -1 */
	char core_binary[PATH_MAX];    /* its executable, without the kernel's " (deleted)" */
	char core_assets[PATH_MAX];    /* geo files directory from its environment, or "" */
};

/* Find v2rayA and its core in /proc through the API socket and the generated config. */
void environment_find_core(const char *api, const char *config_path, struct environment *env);
/* Replace version_data. v2rayA runs its core binary to answer (CheckV5), so
 * callers ask once per v2rayA process rather than every cycle. */
void environment_read_version(const char *api, struct environment *env);
/* Both of the above, from scratch. */
void environment_detect(const char *api, const char *config_path, struct environment *env);
json_object *environment_to_json(const struct environment *env);
void environment_free(struct environment *env);

/* "env API CONFIG": print the environment for rpcd and shell scripts. */
int environment_command(int argc, char **argv);

#endif
