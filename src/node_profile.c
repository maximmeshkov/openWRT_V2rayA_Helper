#include "node_profile.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>

static int only_keys(json_object *obj, const char *const *keys)
{
	if (!json_object_is_type(obj, json_type_object)) return 0;
	json_object_object_foreach(obj, key, value) {
		(void)value;
		const char *const *allowed = keys;
		while (*allowed && strcmp(key, *allowed)) allowed++;
		if (!*allowed) return 0;
	}
	return 1;
}

#define KEYS(obj, ...) only_keys((obj), (const char *const[]){__VA_ARGS__, NULL})

/* Absent fields get their default; null, non-strings and embedded NUL are
 * invalid. In particular, no malformed account may become unauthenticated. */
static const char *text(json_object *obj, const char *key, const char *fallback)
{
	json_object *v;
	if (!json_object_object_get_ex(obj, key, &v)) return fallback;
	if (!json_object_is_type(v, json_type_string)) return NULL;
	const char *s = json_object_get_string(v);
	return strlen(s) == (size_t)json_object_get_string_len(v) ? s : NULL;
}

static json_object *single(json_object *parent, const char *key)
{
	json_object *a = json_object_object_get(parent, key);
	if (!json_object_is_type(a, json_type_array) || json_object_array_length(a) != 1) return NULL;
	return json_object_array_get_idx(a, 0);
}

static int boolean(json_object *obj, const char *key, int *value)
{
	json_object *v;
	if (!json_object_object_get_ex(obj, key, &v)) return 1;
	if (!json_object_is_type(v, json_type_boolean)) return 0;
	*value = json_object_get_boolean(v);
	return 1;
}

static int host_name(const char *s)
{
	if (!s || !*s || strlen(s) > 254) return 0;
	if (strchr(s, ':')) {
		struct in6_addr a;
		return inet_pton(AF_INET6, s, &a) == 1;
	}
	for (const unsigned char *p = (const unsigned char *)s; *p; p++)
		if (!(isalnum(*p) || *p == '.' || *p == '-' || *p == '_')) return 0;
	return 1;
}

static int socket_options(json_object *stream, struct node_profile *p)
{
	json_object *opts, *v;
	if (!json_object_object_get_ex(stream, "sockopt", &opts)) return 1;
	if (!KEYS(opts, "mark")) return 0;
	if (!json_object_object_get_ex(opts, "mark", &v)) return 1;
	if (!json_object_is_type(v, json_type_int)) return 0;
	int64_t mark = json_object_get_int64(v);
	if (mark < 0 || mark > UINT32_MAX) return 0;
	p->has_mark = 1;
	p->mark = (uint32_t)mark;
	return 1;
}

static const char *parse_proxy(json_object *stream, json_object *server, const char *protocol,
                               const char *security, const char *display, struct node_profile *p)
{
	const char *network = text(stream, "network", "tcp");
	if (!network || (*network && strcmp(network, "tcp") && strcmp(network, "raw")) ||
	    (stream && !KEYS(stream, "network", "security", "sockopt", "tlsSettings")))
		return "unsupported proxy stream options";
	json_object *tls = NULL;
	int has_tls = json_object_object_get_ex(stream, "tlsSettings", &tls);
	if (!strcmp(protocol, "http") && !strcmp(security, "tls") && !strcasecmp(display, "https")) {
		if (has_tls && !KEYS(tls, "serverName", "allowInsecure")) return "unsupported HTTPS proxy settings";
		const char *sni = text(tls, "serverName", p->host);
		int allow_insecure = 0;
		if (!sni || (*sni && strcasecmp(sni, p->host)) || !boolean(tls, "allowInsecure", &allow_insecure))
			return "unsupported HTTPS proxy settings";
		if (allow_insecure) return "HTTPS proxy with allowInsecure is unsupported";
		p->kind = NODE_HTTPS;
	} else {
		if (has_tls || (*security && strcmp(security, "none"))) return "unsupported proxy TLS settings";
		if (!strcmp(protocol, "http") && !strcasecmp(display, "http")) p->kind = NODE_HTTP;
		else if (!strcmp(protocol, "socks") && (!strcasecmp(display, "socks5") || !strcasecmp(display, "socks")))
			p->kind = NODE_SOCKS5;
		else return "profile protocol differs from v2rayA";
	}
	json_object *users;
	if (!json_object_object_get_ex(server, "users", &users)) return NULL;
	if (!json_object_is_type(users, json_type_array)) return "unsupported proxy credentials";
	if (!json_object_array_length(users)) return NULL;
	json_object *user = single(server, "users");
	if (!KEYS(user, "user", "pass", "level")) return "unsupported proxy credentials";
	p->username = text(user, "user", NULL);
	p->password = text(user, "pass", NULL);
	if (!p->username || !*p->username || !p->password || !*p->password ||
	    (p->kind == NODE_SOCKS5 && (strlen(p->username) > 255 || strlen(p->password) > 255)) ||
	    (p->kind != NODE_SOCKS5 && strchr(p->username, ':')))
		return "unsupported proxy credentials";
	return NULL;
}

/* A plain SOCKS5 or HTTP(S) proxy that libcurl can reach exactly as configured. */
static const char *parse_native(json_object *core, json_object *stream, const struct member *m,
                                struct node_profile *p)
{
	const char *protocol = text(core, "protocol", NULL), *security = text(stream, "security", "");
	if (!protocol || !security) return "invalid protocol or security";
	if (strcmp(protocol, "http") && strcmp(protocol, "socks")) return "not a plain proxy";
	if (!KEYS(core, "protocol", "tag", "settings", "streamSettings", "mux"))
		return "unsupported outbound options or proxy chain";
	json_object *mux;
	int enabled = 0;
	if (json_object_object_get_ex(core, "mux", &mux) &&
	    (!KEYS(mux, "enabled", "concurrency") || !boolean(mux, "enabled", &enabled) || enabled))
		return "unsupported outbound multiplexing";
	if (!socket_options(stream, p)) return "unsupported socket options";
	json_object *settings = json_object_object_get(core, "settings");
	json_object *server = single(settings, "servers");
	if (!KEYS(settings, "servers") || !KEYS(server, "address", "port", "users"))
		return "unsupported or ambiguous node configuration";
	if (!node_config_endpoint_matches(m->address, server))
		return "profile endpoint differs from v2rayA";
	p->host = text(server, "address", NULL);
	p->port = json_object_get_int(json_object_object_get(server, "port"));
	if (!host_name(p->host)) return "invalid proxy server address";
	return parse_proxy(stream, server, protocol, security, m->display_net, p);
}

/* The core runs any protocol it knows, so only the server's identity is
 * checked: one server with the address and port v2rayA reports. A chain needs
 * outbounds the probe core does not have. */
static const char *parse_core(json_object *core, json_object *stream, const struct member *m,
                              struct node_profile *p)
{
	json_object *settings = json_object_object_get(core, "settings");
	json_object *sockopt = json_object_object_get(stream, "sockopt");
	if (json_object_object_get_ex(core, "proxySettings", NULL) || json_object_object_get_ex(sockopt, "dialerProxy", NULL))
		return "proxy chains are unsupported";
	json_object *server = single(settings, "vnext");
	if (!server) server = single(settings, "servers");
	if (!server) return "outbound has no single server";
	if (!node_config_endpoint_matches(m->address, server))
		return "profile endpoint differs from v2rayA";
	p->host = text(server, "address", NULL);
	p->port = json_object_get_int(json_object_object_get(server, "port"));
	if (!host_name(p->host)) return "invalid server address";
	p->outbound = core;
	p->kind = NODE_CORE;
	return NULL;
}

const char *node_profile_parse(json_object *config, const struct outbound *out,
                              const struct member *m, struct node_profile *p)
{
	*p = (struct node_profile){.username = "", .password = ""};
	json_object *core = node_config_outbound(config, out, m);
	if (!core) return "outbound is missing or ambiguous in the core configuration";
	json_object *stream = NULL;
	if (json_object_object_get_ex(core, "streamSettings", &stream) && !json_object_is_type(stream, json_type_object))
		return "invalid stream settings";
	/* What libcurl cannot express exactly, such as a multiplexed or chained
	 * proxy, goes to the core like every other protocol. */
	if (!parse_native(core, stream, m, p)) return NULL;
	*p = (struct node_profile){.username = "", .password = ""};
	return parse_core(core, stream, m, p);
}
