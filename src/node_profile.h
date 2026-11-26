#ifndef V2RAYA_NODE_PROFILE_H
#define V2RAYA_NODE_PROFILE_H

#include "helper.h"

enum node_kind { NODE_SOCKS5, NODE_HTTP, NODE_HTTPS, NODE_VLESS_XHTTP };

/* All strings borrow storage from the config snapshot. None may be logged or
 * published through ubus. fingerprint describes Xray's configured ClientHello. */
struct node_profile {
	enum node_kind kind;
	const char *host, *username, *password, *uuid;
	const char *sni, *authority, *path, *mode, *fingerprint;
	int port, http_version, allow_insecure, has_mark;
	uint32_t mark;
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

#endif
