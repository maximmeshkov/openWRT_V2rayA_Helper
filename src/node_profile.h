#ifndef V2RAYA_NODE_PROFILE_H
#define V2RAYA_NODE_PROFILE_H

#include "helper.h"

/* libcurl speaks SOCKS5 and HTTP(S) proxies itself. Every other protocol goes
 * through a separate probe core (probe_core.h) that runs the outbound as is. */
enum node_kind { NODE_SOCKS5, NODE_HTTP, NODE_HTTPS, NODE_CORE };

/* All strings borrow storage from the config snapshot. None may be logged or
 * published through ubus. */
struct node_profile {
	enum node_kind kind;
	const char *host, *username, *password;
	int port, has_mark;
	uint32_t mark;
	json_object *outbound; /* NODE_CORE: the outbound to run, borrowed */
};

/* The caller owns the result; json_object_put releases the snapshot. */
json_object *node_config_read(const char *path);
/* NULL means success. Every error is a static, public-safe reason. */
const char *node_profile_parse(json_object *config, const struct outbound *out,
                              const struct member *member, struct node_profile *profile);

/* Shared with inventory's transport classification. Returned JSON is borrowed. */
json_object *node_config_outbound(json_object *config, const struct outbound *out,
                                  const struct member *member);
int node_config_endpoint_matches(const char *api_address, json_object *server);
/* core_port is the probe core's SOCKS port for NODE_CORE, or 0 when none runs. */
struct measurement probe_https_profile(struct node_profile *profile, const struct https_options *options,
                                       uint32_t mark, int core_port, long *http_code);

#endif
