#define _POSIX_C_SOURCE 200809L
#include "helper.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <curl/curl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define RESPONSE_LIMIT (8u * 1024u * 1024u)
#define TOKEN_LIMIT 16384

struct response_body {
	char *bytes;
	size_t len, capacity;
};

static size_t receive_body(char *p, size_t size, size_t count, void *arg)
{
	struct response_body *b = arg;
	if (size != 0 && count > (RESPONSE_LIMIT - b->len) / size)
		return 0;
	size_t n = size * count;
	size_t need = b->len + n + 1;
	if (need > b->capacity) {
		size_t cap = b->capacity ? b->capacity * 2 : 4096;
		if (cap < need)
			cap = need;
		if (cap > RESPONSE_LIMIT + 1)
			cap = RESPONSE_LIMIT + 1;
		char *buf = realloc(b->bytes, cap);
		if (!buf)
			return 0;
		b->bytes = buf;
		b->capacity = cap;
	}
	memcpy(b->bytes + b->len, p, n);
	b->len += n;
	b->bytes[b->len] = '\0';
	return n;
}

// Verify the API origin before reading or sending any token.
static int valid_url(const char *base, int loopback_only)
{
	CURLU *u = curl_url();
	char *scheme = NULL, *host = NULL;
	int valid = 0;
	if (!u || !base || strpbrk(base, "?#") ||
	    curl_url_set(u, CURLUPART_URL, base, CURLU_DISALLOW_USER) != CURLUE_OK ||
	    curl_url_get(u, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK ||
	    curl_url_get(u, CURLUPART_HOST, &host, 0) != CURLUE_OK)
		goto done;
	if (strcmp(scheme, "https") == 0 && !loopback_only) {
		valid = 1;
	} else if (!strcmp(scheme, "http") || !strcmp(scheme, "https")) {
		struct in_addr ipv4;
		valid = strcmp(host, "[::1]") == 0 ||
		        (inet_pton(AF_INET, host, &ipv4) == 1 && (ntohl(ipv4.s_addr) >> 24) == 127);
	}
done:
	curl_free(scheme);
	curl_free(host);
	curl_url_cleanup(u);
	return valid;
}

int valid_observatory_url(const char *url)
{
	return valid_url(url, 1);
}

static int read_token(const char *path, char token[TOKEN_LIMIT + 2])
{
	token[0] = '\0';
	if (!path || !*path)
		return 0;
	FILE *fp = fopen(path, "rb");
	if (!fp)
		return -1;
	size_t n = fread(token, 1, TOKEN_LIMIT + 1, fp);
	int failed = ferror(fp);
	fclose(fp);
	if (failed || n > TOKEN_LIMIT)
		return -1;
	while (n && isspace((unsigned char)token[n-1]))
		n--;
	if (!n)
		return -1;
	if (memchr(token, '\0', n))
		return -1;
	token[n] = '\0';
	return 0;
}

static const char *json_text(json_object *o)
{
	if (!json_object_is_type(o, json_type_string))
		return NULL;
	const char *s = json_object_get_string(o);
	return strlen(s) == (size_t)json_object_get_string_len(o) ? s : NULL;
}

static const char *field_text(json_object *obj, const char *key)
{
	json_object *o = NULL;
	json_object_object_get_ex(obj, key, &o);
	return json_text(o);
}

json_object *fetch_json(const char *url, const char *token, long timeout_ms, char *error, size_t error_len)
{
	if (!valid_url(url, 0) || timeout_ms <= 0) {
		snprintf(error, error_len, "invalid URL or timeout; use HTTPS or a loopback HTTP IP");
		return NULL;
	}
	struct curl_slist *headers = NULL;
	if (token && *token) {
		size_t length = strlen(token);
		if (length > TOKEN_LIMIT) {
			snprintf(error, error_len, "invalid authorization token");
			return NULL;
		}
		for (size_t i = 0; i < length; i++)
			if ((unsigned char)token[i] < 33 || (unsigned char)token[i] >= 127) {
				snprintf(error, error_len, "invalid authorization token");
				return NULL;
			}
		char line[sizeof("Authorization: Bearer ") + TOKEN_LIMIT];
		snprintf(line, sizeof(line), "Authorization: Bearer %s", token);
		headers = curl_slist_append(NULL, line);
		if (!headers) {
			snprintf(error, error_len, "out of memory");
			return NULL;
		}
	}
	CURL *curl = curl_easy_init();
	struct response_body body = {0};
	json_object *root = NULL;
	/* Control-plane reads run on the main thread, outside the probe batch.
	 * For remote HTTPS on a synchronous libcurl, allow its DNS timeout. */
	long no_signal = valid_observatory_url(url) ||
		(curl_version_info(CURLVERSION_NOW)->features & CURL_VERSION_ASYNCHDNS);
	if (!curl || curl_easy_setopt(curl, CURLOPT_URL, url) ||
	    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) ||
	    curl_easy_setopt(curl, CURLOPT_PROXY, "") || curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L) ||
	    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, no_signal) || curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms) ||
	    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_body) || curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body)) {
		snprintf(error, error_len, "cannot initialize HTTP client");
		goto done;
	}
	CURLcode rc = curl_easy_perform(curl);
	long status = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
	if (status == 401 || status == 403) {
		snprintf(error, error_len, "authorization required (HTTP %ld)", status);
		goto done;
	}
	if (rc != CURLE_OK || status != 200 || !body.bytes) {
		snprintf(error, error_len, "HTTP request failed (HTTP %ld, curl %d)", status, (int)rc);
		goto done;
	}
	json_tokener *tok = json_tokener_new();
	if (tok) {
		json_tokener_set_flags(tok, JSON_TOKENER_STRICT);
		root = json_tokener_parse_ex(tok, body.bytes, (int)body.len);
		json_tokener_free(tok);
	}
	if (!root)
		snprintf(error, error_len, "invalid JSON response");
done:
	curl_easy_cleanup(curl);
	curl_slist_free_all(headers);
	free(body.bytes);
	return root;
}

static json_object *get_data(const char *base, const char *endpoint, const char *token,
                             long timeout_ms, char *error, size_t error_len)
{
	size_t n = strlen(base);
	while (n && base[n-1] == '/')
		n--;
	size_t cap = n + strlen(endpoint) + sizeof("/api/");
	char *url = malloc(cap);
	if (!url) {
		snprintf(error, error_len, "out of memory");
		return NULL;
	}
	memcpy(url, base, n);
	snprintf(url + n, cap - n, "/api/%s", endpoint);
	json_object *envelope = fetch_json(url, token, timeout_ms, error, error_len);
	free(url);
	if (!envelope)
		return NULL;
	json_object *result = NULL;
	const char *code = field_text(envelope, "code");
	const char *message = field_text(envelope, "message");
	if (!code || strcmp(code, "SUCCESS") != 0) {
		// Upstream messages and bodies may contain subscription URLs.
		const char *reason = field_text(envelope, "errorCode");
		if ((code && !strcmp(code, "UNAUTHORIZED")) || (message && !strcmp(message, "expired token")) ||
		    (reason && (!strcmp(reason, "SESSION_INVALID") || !strcmp(reason, "SESSION_EXPIRED"))))
			snprintf(error, error_len, "v2rayA authorization required");
		else
			snprintf(error, error_len, "v2rayA %s response unavailable or busy", endpoint);
		goto done;
	}
	json_object *data = NULL;
	if (json_object_object_get_ex(envelope, "data", &data) && json_object_is_type(data, json_type_object))
		result = json_object_get(data);
	else
		snprintf(error, error_len, "invalid v2rayA %s response", endpoint);
done:
	json_object_put(envelope);
	return result;
}

// The API exposes display text. Bare Trojan can conceal mKCP, and XHTTP
// can negotiate HTTP/3. Such labels cannot safely select a TCP probe.
static const char *server_transport(const char *display)
{
	if (!strcasecmp(display, "http") || !strcasecmp(display, "https") ||
	    !strcasecmp(display, "socks") || !strcasecmp(display, "socks5") || !strcasecmp(display, "anytls"))
		return "tcp";
	if (!strcasecmp(display, "juicity") || !strcasecmp(display, "tuic") || !strcasecmp(display, "hysteria2"))
		return "quic";
	if (!strcasecmp(display, "wireguard"))
		return "udp";
	if ((strncasecmp(display, "vless(", 6) && strncasecmp(display, "vmess(", 6)) ||
	    display[strlen(display) - 1] != ')')
		return "unknown";
	const char *network = display + 6;
	static const struct { const char *net, *transport; } known[] = {
		{"tcp", "tcp"}, {"raw", "tcp"}, {"ws", "tcp"}, {"websocket", "tcp"},
		{"grpc", "tcp"}, {"h2", "tcp"}, {"httpupgrade", "tcp"},
		{"quic", "udp"}, {"kcp", "udp"}, {"mkcp", "udp"}
	};
	size_t len = strcspn(network, "+)");
	for (size_t i = 0; i < sizeof(known)/sizeof(known[0]); i++)
		if (strlen(known[i].net) == len && !strncasecmp(network, known[i].net, len))
			return known[i].transport;
	return "unknown";
}

void free_inventory(struct inventory *inv)
{
	for (size_t i = 0; i < inv->count; i++) {
		struct outbound *o = &inv->outbounds[i];
		for (size_t j = 0; j < o->count; j++) {
			free(o->members[j].name);
			free(o->members[j].address);
			free(o->members[j].transport);
			free(o->members[j].display_net);
		}
		free(o->members);
		free(o->name);
	}
	free(inv->outbounds);
	*inv = (struct inventory){0};
}

static struct outbound *find_outbound(struct inventory *inv, const char *name)
{
	for (size_t i = 0; i < inv->count; i++)
		if (!strcmp(name, inv->outbounds[i].name))
			return &inv->outbounds[i];
	return NULL;
}

static int64_t field_int(json_object *obj, const char *key)
{
	json_object *v = NULL;
	json_object_object_get_ex(obj, key, &v);
	return json_object_is_type(v, json_type_int) ? json_object_get_int64(v) : -1;
}

static int add_member(struct outbound *out, json_object *server, json_object *ref)
{
	const char *name = field_text(server, "name");
	const char *address = field_text(server, "address");
	const char *net = field_text(server, "net");
	if (!name || !address || !net)
		return -1;
	struct member *grown = realloc(out->members, (out->count + 1) * sizeof(*grown));
	if (!grown)
		return -1;
	out->members = grown;
	struct member *m = &grown[out->count++];
	json_object *selected = NULL;
	json_object_object_get_ex(ref, "selected", &selected);
	*m = (struct member){
		.name = strdup(name), .address = strdup(address), .transport = strdup(server_transport(net)),
		.display_net = strdup(net), .node_id = field_int(ref, "id"),
		.subscription = !strcmp(field_text(ref, "_type"), "server") ? -1 : field_int(ref, "sub"),
		.selected = json_object_is_type(selected, json_type_boolean) && json_object_get_boolean(selected)
	};
	return m->name && m->address && m->transport && m->display_net ? 0 : -1;
}

static int parse_inventory(json_object *names_data, json_object *touch_data, struct inventory *inv)
{
	json_object *names = NULL, *running = NULL, *touch = NULL;
	json_object *servers = NULL, *subs = NULL, *refs = NULL;
	if (!json_object_object_get_ex(names_data, "outbounds", &names) || !json_object_is_type(names, json_type_array) ||
	    !json_object_array_length(names) || !json_object_object_get_ex(touch_data, "running", &running) ||
	    !json_object_is_type(running, json_type_boolean) || !json_object_object_get_ex(touch_data, "touch", &touch) ||
	    !json_object_object_get_ex(touch, "servers", &servers) || !json_object_is_type(servers, json_type_array) ||
	    !json_object_object_get_ex(touch, "subscriptions", &subs) || !json_object_is_type(subs, json_type_array) ||
	    !json_object_object_get_ex(touch, "connectedServer", &refs) || (refs && !json_object_is_type(refs, json_type_array)))
		return -1;
	inv->running = json_object_get_boolean(running);
	json_object *paused = NULL;
	if (json_object_object_get_ex(touch_data, "networkPaused", &paused)) {
		if (!json_object_is_type(paused, json_type_boolean))
			return -1;
		if (json_object_get_boolean(paused))
			inv->running = 0;
	}
	size_t n = json_object_array_length(names);
	inv->outbounds = calloc(n, sizeof(*inv->outbounds));
	if (!inv->outbounds)
		return -1;
	for (size_t i = 0; i < n; i++) {
		const char *name = json_text(json_object_array_get_idx(names, i));
		if (!name || !*name || find_outbound(inv, name))
			return -1;
		inv->outbounds[i].name = strdup(name);
		if (!inv->outbounds[i].name)
			return -1;
		inv->count++;
	}
	// Empty sets of assigned servers can be encoded as JSON null.
	for (size_t i = 0; refs && i < json_object_array_length(refs); i++) {
		json_object *ref = json_object_array_get_idx(refs, i);
		const char *outbound = field_text(ref, "outbound");
		const char *type = field_text(ref, "_type");
		int64_t id = field_int(ref, "id");
		struct outbound *out = find_outbound(inv, outbound && *outbound ? outbound : "proxy");
		json_object *list = servers;
		if (!type || !out || id < 1)
			return -1;
		if (!strcmp(type, "subscriptionServer")) {
			// Server IDs are one-based positions. The subscription index is zero-based.
			int64_t sub = field_int(ref, "sub");
			if (sub < 0 || (uint64_t)sub >= json_object_array_length(subs))
				return -1;
			json_object *subscription = json_object_array_get_idx(subs, (size_t)sub);
			if (!json_object_object_get_ex(subscription, "servers", &list) || !json_object_is_type(list, json_type_array))
				return -1;
		} else if (strcmp(type, "server")) {
			return -1;
		}
		if ((uint64_t)id > json_object_array_length(list))
			return -1;
		json_object *server = json_object_array_get_idx(list, (size_t)id - 1);
		if (field_int(server, "id") != id || add_member(out, server, ref))
			return -1;
	}
	return 0;
}

int load_inventory(const char *api, const char *token_file, long timeout_ms,
                   struct inventory *out, char *error, size_t error_len)
{
	*out = (struct inventory){0};
	if (!valid_url(api, 0) || timeout_ms <= 0) {
		snprintf(error, error_len, "invalid v2rayA URL or timeout; use HTTPS or a loopback HTTP IP");
		return -1;
	}
	char token[TOKEN_LIMIT + 2];
	if (read_token(token_file, token)) {
		snprintf(error, error_len, "cannot read v2rayA authorization token");
		return -1;
	}
	int rc = -1;
	json_object *names = NULL, *touch = NULL;
	names = get_data(api, "outbounds", token, timeout_ms, error, error_len);
	if (!names)
		goto done;
	touch = get_data(api, "touch", token, timeout_ms, error, error_len);
	if (!touch)
		goto done;
	if (parse_inventory(names, touch, out)) {
		snprintf(error, error_len, "incomplete or inconsistent v2rayA inventory");
		free_inventory(out);
		goto done;
	}
	rc = 0;
done:
	json_object_put(names);
	json_object_put(touch);
	return rc;
}
