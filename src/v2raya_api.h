#ifndef V2RAYA_HELPER_V2RAYA_API_H
#define V2RAYA_HELPER_V2RAYA_API_H

#include <stddef.h>
#include <json-c/json.h>

/* Curl pre-request callback. Return zero only for the verified local transport's peer. */
typedef int (*v2raya_login_peer)(void *context, char *remote_ip, char *local_ip,
                                 int remote_port, int local_port);

struct v2raya_api {
	const char *base;
	const char *token_file;
	long timeout_ms;
	v2raya_login_peer connected_peer;
	void *peer_context;
};

/* Return caller-owned strings or NULL on failure. */
char *v2raya_api_get_version(const struct v2raya_api *api, char *error, size_t len);
char *v2raya_api_get_routing(const struct v2raya_api *api, char *error, size_t len);

/* Return 0 after v2rayA acknowledges the write. Recheck the version and
 * current document first; the upstream API cannot make the check atomic. */
int v2raya_api_save_routing(const struct v2raya_api *api, const char *expected_original,
                          const char *routing, char *error, size_t len);

/* Internal connections API. The decoded version and touch data are owned by
 * the caller. The `which` objects contain a validated saved-server reference. */
json_object *v2raya_api_version_data(const struct v2raya_api *api, char *error, size_t len);
json_object *v2raya_api_touch_data(const struct v2raya_api *api, char *error, size_t len);
json_object *v2raya_api_setting_data(const struct v2raya_api *api, char *error, size_t len);
char *v2raya_api_export_node(const struct v2raya_api *api, json_object *which, char *error, size_t len);
json_object *v2raya_api_connect_node(const struct v2raya_api *api, json_object *which,
                                   int (*permitted)(void *), void *context, char *error, size_t len);
int v2raya_api_start_core(const struct v2raya_api *api, v2raya_login_peer permitted, void *context,
                         char *error, size_t len);

/* True only for an authenticated, explicit api.port of zero. */
int v2raya_api_core_port_automatic(const struct v2raya_api *api, v2raya_login_peer peer,
                                   void *context, char *error, size_t len);
/* Returns 0/1 for the configured setting, or -1 if it could not be read. */
int v2raya_api_port_sharing(const struct v2raya_api *api, v2raya_login_peer peer,
                            void *context, char *error, size_t len);
char *v2raya_api_login_token(const struct v2raya_api *api, const char *username, const char *password,
                            v2raya_login_peer peer, void *context, char *error, size_t len);

#endif
