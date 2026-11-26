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

static int ascii_line(const char *s)
{
	if (!s) return 0;
	for (const unsigned char *p = (const unsigned char *)s; *p; p++)
		if (*p <= 32 || *p >= 127) return 0;
	return 1;
}

static int authority_ok(const char *s)
{
	if (!ascii_line(s) || !*s || strlen(s) > 262) return 0;
	return strspn(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.:[]") == strlen(s);
}

static int valid_uuid(const char *s)
{
	if (!s) return 0;
	size_t len = strlen(s);
	if (len != 32 && len != 36) return 0;
	for (size_t i = 0; i < len; i++) {
		if (len == 36 && (i == 8 || i == 13 || i == 18 || i == 23)) {
			if (s[i] != '-') return 0;
		} else if (!isxdigit((unsigned char)s[i])) return 0;
	}
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

static int parse_alpn(json_object *tls, struct node_profile *p)
{
	p->http_version = 2;
	json_object *v;
	if (!json_object_object_get_ex(tls, "alpn", &v)) return 1;
	if (!json_object_is_type(v, json_type_array)) return 0;
	size_t count = json_object_array_length(v);
	int h2 = 0;
	for (size_t i = 0; i < count; i++) {
		json_object *entry = json_object_array_get_idx(v, i);
		if (!json_object_is_type(entry, json_type_string)) return 0;
		const char *s = json_object_get_string(entry);
		if (strlen(s) != (size_t)json_object_get_string_len(entry)) return 0;
		if (!strcmp(s, "h2")) h2 = 1;
		else if (!strcmp(s, "http/1.1")) {
			if (count == 1) p->http_version = 1;
		} else if (strcmp(s, "h3")) return 0;
	}
	return !count || h2 || p->http_version == 1;
}

static const char *parse_xhttp(json_object *stream, json_object *server, struct node_profile *p)
{
	json_object *tls = NULL, *xhttp = NULL, *alias;
	if (!KEYS(stream, "network", "security", "tlsSettings", "xhttpSettings", "splithttpSettings", "sockopt"))
		return "unsupported XHTTP stream options";
	if (json_object_object_get_ex(stream, "tlsSettings", &tls) &&
	    !KEYS(tls, "serverName", "alpn", "allowInsecure", "fingerprint"))
		return "unsupported TLS settings";
	if (!parse_alpn(tls, p)) return "unsupported XHTTP ALPN";
	p->sni = text(tls, "serverName", "");
	p->fingerprint = text(tls, "fingerprint", "");
	if (!p->sni || !ascii_line(p->fingerprint) || !boolean(tls, "allowInsecure", &p->allow_insecure))
		return "invalid TLS settings";
	if (!*p->sni) p->sni = p->host;
	if (!host_name(p->sni)) return "unsupported TLS server name";
	int has_xhttp = json_object_object_get_ex(stream, "xhttpSettings", &xhttp);
	if (json_object_object_get_ex(stream, "splithttpSettings", &alias)) {
		if (has_xhttp) return "ambiguous XHTTP settings";
		xhttp = alias;
		has_xhttp = 1;
	}
	if (has_xhttp && !KEYS(xhttp, "path", "mode", "host")) return "unsupported XHTTP settings";
	p->authority = text(xhttp, "host", "");
	p->path = text(xhttp, "path", "/");
	p->mode = text(xhttp, "mode", "auto");
	if (!p->authority || !p->mode || !p->path || strlen(p->path) > 4096)
		return "invalid XHTTP settings";
	const char *query = strchr(p->path, '?');
	if (query && (!ascii_line(query) || strchr(query, '#'))) return "invalid XHTTP query";
	for (const unsigned char *c = (const unsigned char *)p->path; *c && *c != '?'; c++)
		if (*c < 32 || *c == 127) return "invalid XHTTP path";
	/* The relay derives a missing authority from SNI/destination and adds
	 * the brackets required in a URL authority for an IPv6 destination. */
	if (*p->authority && !authority_ok(p->authority)) return "unsupported XHTTP authority";
	if (!*p->path) p->path = "/";
	if (!*p->mode || !strcmp(p->mode, "auto")) p->mode = "packet-up";
	if (strcmp(p->mode, "packet-up") && strcmp(p->mode, "stream-up") && strcmp(p->mode, "stream-one"))
		return "unsupported XHTTP mode";
	if (p->http_version == 1 && strcmp(p->mode, "packet-up"))
		return "XHTTP stream modes require HTTP/2 in this helper";

	json_object *user = single(server, "users");
	if (!KEYS(user, "id", "encryption", "flow", "email", "level")) return "unsupported VLESS account";
	const char *encryption = text(user, "encryption", NULL), *flow = text(user, "flow", "");
	p->uuid = text(user, "id", NULL);
	if (!valid_uuid(p->uuid) || !encryption || strcmp(encryption, "none") || !flow || *flow)
		return "unsupported VLESS account";
	p->kind = NODE_VLESS_XHTTP;
	return NULL;
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
		p->sni = text(tls, "serverName", p->host);
		if (!p->sni || (*p->sni && strcasecmp(p->sni, p->host)) ||
		    !boolean(tls, "allowInsecure", &p->allow_insecure))
			return "unsupported HTTPS proxy settings";
		if (p->allow_insecure) return "HTTPS proxy with allowInsecure is unsupported";
		p->sni = p->host;
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

const char *node_profile_parse(json_object *config, const struct outbound *out,
                              const struct member *m, struct node_profile *p)
{
	*p = (struct node_profile){ .username = "", .password = "", .uuid = "", .sni = "",
	                            .authority = "", .path = "", .mode = "", .fingerprint = "" };
	json_object *core = node_config_outbound(config, out, m);
	if (!core) return "outbound is missing or ambiguous in the core configuration";
	if (!KEYS(core, "protocol", "tag", "settings", "streamSettings", "mux"))
		return "unsupported outbound options or proxy chain";
	json_object *mux;
	int enabled = 0;
	if (json_object_object_get_ex(core, "mux", &mux) &&
	    (!KEYS(mux, "enabled", "concurrency") || !boolean(mux, "enabled", &enabled) || enabled))
		return "unsupported outbound multiplexing";
	json_object *settings = json_object_object_get(core, "settings"), *stream = NULL;
	if (json_object_object_get_ex(core, "streamSettings", &stream) &&
	    !json_object_is_type(stream, json_type_object))
		return "invalid stream settings";
	if (!socket_options(stream, p)) return "unsupported socket options";
	const char *protocol = text(core, "protocol", NULL), *security = text(stream, "security", "");
	if (!protocol || !security) return "invalid protocol or security";
	int vless = !strcmp(protocol, "vless");
	if (!vless && strcmp(protocol, "http") && strcmp(protocol, "socks"))
		return "unsupported node protocol";
	const char *list = vless ? "vnext" : "servers";
	json_object *server = single(settings, list);
	if (!KEYS(settings, list) || !KEYS(server, "address", "port", "users"))
		return "unsupported or ambiguous node configuration";
	if (!node_config_endpoint_matches(m->address, server))
		return "profile endpoint differs from v2rayA";
	p->host = text(server, "address", NULL);
	p->port = json_object_get_int(json_object_object_get(server, "port"));
	if (!host_name(p->host)) return "invalid proxy server address";
	if (!vless) return parse_proxy(stream, server, protocol, security, m->display_net, p);
	const char *network = text(stream, "network", NULL);
	if (!network || strcmp(security, "tls") ||
	    !((!strcmp(network, "xhttp") && !strcasecmp(m->display_net, "vless(xhttp+tls)")) ||
	      (!strcmp(network, "splithttp") && !strcasecmp(m->display_net, "vless(splithttp+tls)"))))
		return "unsupported or mismatched VLESS transport";
	return parse_xhttp(stream, server, p);
}
