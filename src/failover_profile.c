#include "failover_profile.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define SHARE_URI_LIMIT 16384

/* A reserve server comes from v2rayA's own export (GET /api/sharingAddress).
 * The outbound built here repeats Configuration() of its server objects
 * (service/core/serverObj/{v2ray,trojan,shadowsocks}.go@v2.2.7.4), so the probe
 * core runs what v2rayA would run after a switch. */

/* Query keys of the vless:// and trojan:// exports, then the vmess:// JSON-only fields. */
enum field {
    F_TYPE, F_SECURITY, F_PATH, F_HOST, F_HEADER_TYPE, F_SEED, F_SERVICE_NAME, F_KEY, F_QUIC_SECURITY,
    F_FLOW, F_SNI, F_ALPN, F_INSECURE, F_FP, F_PBK, F_SID, F_SPX, F_ID, F_AID, F_SCY, FIELD_COUNT
};
static const char *const query_keys[FIELD_COUNT] = {
    [F_TYPE] = "type", [F_SECURITY] = "security", [F_PATH] = "path", [F_HOST] = "host",
    [F_HEADER_TYPE] = "headerType", [F_SEED] = "seed", [F_SERVICE_NAME] = "serviceName", [F_KEY] = "key",
    [F_QUIC_SECURITY] = "quicSecurity", [F_FLOW] = "flow", [F_SNI] = "sni", [F_ALPN] = "alpn",
    [F_INSECURE] = "allowInsecure", [F_FP] = "fp", [F_PBK] = "pbk", [F_SID] = "sid", [F_SPX] = "spx",
};
/* The same fields under the names of v2rayA's vmess JSON (V2Ray struct tags). */
static const char *const vmess_keys[FIELD_COUNT] = {
    [F_TYPE] = "net", [F_SECURITY] = "tls", [F_PATH] = "path", [F_HOST] = "host", [F_HEADER_TYPE] = "type",
    [F_KEY] = "key", [F_QUIC_SECURITY] = "quicSecurity", [F_FLOW] = "flow", [F_SNI] = "sni", [F_ALPN] = "alpn",
    [F_FP] = "fingerprint", [F_PBK] = "pbk", [F_SID] = "sid", [F_SPX] = "spx", [F_ID] = "id", [F_AID] = "aid",
    [F_SCY] = "scy",
};

static int hex_value(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int valid_uri_bytes(const char *uri)
{
    for (const unsigned char *p = (const unsigned char *)uri; *p; ++p) {
        if (*p <= 32 || *p >= 127 || *p == '\\') return 0;
        if (*p == '%') {
            if (hex_value(p[1]) < 0 || hex_value(p[2]) < 0) return 0;
            p += 2;
        }
    }
    return 1;
}

/* Split first, then decode. Encoded separators belong to parameter values. */
static char *decode_query(const char *start, const char *end)
{
    char *result = malloc((size_t)(end - start) + 1);
    if (!result) return NULL;
    char *out = result;
    while (start < end) {
        unsigned char c = (unsigned char)*start++;
        if (c == '%') {
            if (end - start < 2) goto invalid;
            int high = hex_value(start[0]), low = hex_value(start[1]);
            if (high < 0 || low < 0) goto invalid;
            c = (unsigned char)((high << 4) | low);
            start += 2;
        } else if (c == '+') {
            c = ' ';
        }
        if (c < 32 || c == 127) goto invalid;
        *out++ = (char)c;
    }
    *out = '\0';
    return result;
invalid:
    free(result);
    return NULL;
}

static int parse_query(const char *query, char *field[FIELD_COUNT])
{
    while (query && *query) {
        const char *end = strchr(query, '&');
        if (!end) end = query + strlen(query);
        const char *eq = memchr(query, '=', (size_t)(end - query));
        if (!eq) return 0;
        size_t pos = 0, key_length = (size_t)(eq - query);
        while (pos < FIELD_COUNT && (!query_keys[pos] || strlen(query_keys[pos]) != key_length ||
                                     memcmp(query, query_keys[pos], key_length))) ++pos;
        if (pos == FIELD_COUNT || field[pos]) return 0;
        field[pos] = decode_query(eq + 1, end);
        if (!field[pos]) return 0;
        if (!*end) return 1;
        query = end + 1;
    }
    return 1;
}

/* Standard or URL alphabet, padding optional: v2rayA trims it from vmess:// and ss://. */
static char *base64_decode(const char *text, size_t length)
{
    char *out = malloc(length / 4 * 3 + 4);
    if (!out) return NULL;
    size_t used = 0;
    unsigned int bits = 0, count = 0;
    for (size_t i = 0; i < length && text[i] != '='; i++) {
        const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        char c = text[i] == '-' ? '+' : text[i] == '_' ? '/' : text[i];
        const char *at = c ? strchr(alphabet, c) : NULL;
        if (!at) goto invalid;
        bits = bits << 6 | (unsigned int)(at - alphabet);
        if ((count += 6) >= 8) {
            count -= 8;
            out[used++] = (char)(bits >> count & 0xff);
        }
    }
    out[used] = '\0';
    if (strlen(out) == used) return out;
invalid:
    free(out);
    return NULL;
}

static int put(json_object *obj, const char *key, json_object *value)
{
    if (!value) return 0;
    int rc = key ? json_object_object_add(obj, key, value) : json_object_array_add(obj, value);
    if (!rc) return 1;
    json_object_put(value);
    return 0;
}

static json_object *object(json_object *parent, const char *key)
{
    json_object *child = json_object_new_object();
    return put(parent, key, child) ? child : NULL;
}

static json_object *array(json_object *parent, const char *key)
{
    json_object *child = json_object_new_array();
    return put(parent, key, child) ? child : NULL;
}

static int put_string(json_object *obj, const char *key, const char *value)
{
    return put(obj, key, json_object_new_string(value));
}

static const char *or_empty(const char *text) { return text ? text : ""; }

/* strings.Split(text, ","), optionally trimming spaces like the ALPN list. */
static int put_list(json_object *parent, const char *key, const char *text, int trim)
{
    json_object *entries = array(parent, key);
    if (!entries) return 0;
    for (;;) {
        const char *end = strchr(text, ',');
        if (!end) end = text + strlen(text);
        const char *start = text, *last = end;
        while (trim && start < last && *start == ' ') ++start;
        while (trim && last > start && last[-1] == ' ') --last;
        if (!put(entries, NULL, json_object_new_string_len(start, (int)(last - start))))
            return 0;
        if (!*end) return 1;
        text = end + 1;
    }
}

static int put_strings(json_object *parent, const char *key, const char *const *values)
{
    json_object *entries = array(parent, key);
    while (entries && *values)
        if (!put(entries, NULL, json_object_new_string(*values++))) return 0;
    return entries != NULL;
}

/* The obfuscating HTTP header of a TCP transport (v2ray.go, case "tcp"). */
static int put_http_header(json_object *stream, const char *host, const char *path)
{
    static const char *const agents[] = {
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/53.0.2785.109 Mobile/14A456 Safari/601.1.46",
        NULL};
    static const char *const encoding[] = {"gzip, deflate", NULL}, *const alive[] = {"keep-alive", NULL};
    static const char *const types[] = {"application/octet-stream", "video/mpeg", NULL};
    static const char *const chunked[] = {"chunked", NULL};
    json_object *tcp = object(stream, "tcpSettings"), *header = tcp ? object(tcp, "header") : NULL;
    json_object *request = header ? object(header, "request") : NULL, *response = header ? object(header, "response") : NULL;
    json_object *ask = request ? object(request, "headers") : NULL, *answer = response ? object(response, "headers") : NULL;
    json_object *paths = request ? array(request, "path") : NULL;
    if (!ask || !answer || !paths || !put_string(header, "type", "http") ||
        !put_string(request, "version", "1.1") || !put_string(request, "method", "GET") ||
        !put_list(ask, "Host", host, 0) || !put_strings(ask, "User-Agent", agents) ||
        !put_strings(ask, "Accept-Encoding", encoding) || !put_strings(ask, "Connection", alive) ||
        !put_string(ask, "Pragma", "no-cache") || !put_string(response, "version", "1.1") ||
        !put_string(response, "status", "200") || !put_string(response, "reason", "OK") ||
        !put_strings(answer, "Content-Type", types) || !put_strings(answer, "Transfer-Encoding", chunked) ||
        !put_strings(answer, "Connection", alive) || !put_string(answer, "Pragma", "no-cache")) return 0;
    if (!*path) return put(paths, NULL, json_object_new_string("/"));
    for (const char *item = path;;) {
        const char *end = strchr(item, ',');
        if (!end) end = item + strlen(item);
        char entry[4097];
        int length = snprintf(entry, sizeof(entry), "%s%.*s", *item == '/' ? "" : "/", (int)(end - item), item);
        if (length < 0 || (size_t)length >= sizeof(entry) || !put(paths, NULL, json_object_new_string(entry)))
            return 0;
        if (!*end) return 1;
        item = end + 1;
    }
}

static int put_kcp(json_object *stream, const char *header_type, const char *seed)
{
    json_object *kcp = object(stream, "kcpSettings"), *header = kcp ? object(kcp, "header") : NULL;
    return header && put(kcp, "mtu", json_object_new_int(1350)) && put(kcp, "tti", json_object_new_int(50)) &&
           put(kcp, "uplinkCapacity", json_object_new_int(12)) && put(kcp, "downlinkCapacity", json_object_new_int(100)) &&
           put(kcp, "congestion", json_object_new_boolean(0)) && put(kcp, "readBufferSize", json_object_new_int(2)) &&
           put(kcp, "writeBufferSize", json_object_new_int(2)) && put_string(header, "type", header_type) &&
           put_string(kcp, "seed", seed);
}

/* Transport settings shared by v2ray.go and trojan.go; only v2ray.go knows
 * tcp headers, quic and xhttp, and rejects other names. */
static const char *put_transport(json_object *stream, char *f[FIELD_COUNT], int v2ray)
{
    const char *net = or_empty(f[F_TYPE]), *path = or_empty(f[F_PATH]), *host = or_empty(f[F_HOST]);
    const char *header_type = or_empty(f[F_HEADER_TYPE]);
    json_object *settings;
    if (!strcasecmp(net, "grpc")) {
        settings = object(stream, "grpcSettings");
        return settings && put_string(settings, "serviceName", *path ? path : "GunService") ? NULL : "out of memory";
    }
    if (!strcasecmp(net, "ws")) {
        settings = object(stream, "wsSettings");
        json_object *headers = settings ? object(settings, "headers") : NULL;
        return headers && put_string(settings, "path", path) && put_string(headers, "Host", host) ? NULL : "out of memory";
    }
    if (!strcasecmp(net, "mkcp") || !strcasecmp(net, "kcp"))
        return put_kcp(stream, header_type, path) ? NULL : "out of memory";
    if (!strcasecmp(net, "h2") || !strcasecmp(net, "http")) {
        settings = object(stream, "httpSettings");
        return settings && put_string(settings, "path", path) && (!*host || put_list(settings, "host", host, 0)) ?
               NULL : "out of memory";
    }
    if (!v2ray) return NULL;
    if (!strcasecmp(net, "tcp"))
        return strcasecmp(header_type, "http") || put_http_header(stream, host, path) ? NULL : "out of memory";
    if (!strcasecmp(net, "quic")) {
        settings = object(stream, "quicSettings");
        json_object *header = settings ? object(settings, "header") : NULL;
        return header && put_string(header, "type", header_type) && put_string(settings, "key", or_empty(f[F_KEY])) &&
               put_string(settings, "security", or_empty(f[F_QUIC_SECURITY])) ? NULL : "out of memory";
    }
    if (!strcasecmp(net, "xhttp")) {
        settings = object(stream, "xhttpSettings");
        return settings && put_string(settings, "path", path) ? NULL : "out of memory";
    }
    return "unsupported catalog transport";
}

static int put_tls(json_object *stream, const char *key, char *f[FIELD_COUNT], int insecure)
{
    const char *sni = or_empty(f[F_SNI]), *host = or_empty(f[F_HOST]);
    json_object *tls = object(stream, key);
    return tls && (!insecure || put(tls, "allowInsecure", json_object_new_boolean(1))) &&
           (!*(*sni ? sni : host) || put_string(tls, "serverName", *sni ? sni : host)) &&
           (!f[F_ALPN] || !*f[F_ALPN] || put_list(tls, "alpn", f[F_ALPN], 1)) &&
           (strcmp(key, "tlsSettings") || put_string(tls, "fingerprint", or_empty(f[F_FP])));
}

/* VMess or VLESS from the normalised fields (V2Ray.Configuration). */
static const char *v2ray_outbound(json_object *out, const char *protocol, const char *address, int port,
                                  char *f[FIELD_COUNT])
{
    const char *id = or_empty(f[F_ID]);
    if (strlen(id) < 32 || strlen(id) > 36) return "unsupported catalog account";  /* v2rayA hashes it to a UUID */
    int vmess = !strcmp(protocol, "vmess");
    const char *scy = f[F_SCY] && *f[F_SCY] ? f[F_SCY] : "auto";
    json_object *settings = object(out, "settings"), *vnext = settings ? array(settings, "vnext") : NULL;
    json_object *server = vnext ? object(vnext, NULL) : NULL, *users = server ? array(server, "users") : NULL;
    json_object *user = users ? object(users, NULL) : NULL, *stream = object(out, "streamSettings");
    if (!user || !stream || !put_string(out, "protocol", protocol) || !put_string(server, "address", address) ||
        !put(server, "port", json_object_new_int(port)) || !put_string(user, "id", id) ||
        (vmess ? !put(user, "alterId", json_object_new_int(atoi(or_empty(f[F_AID])))) || !put_string(user, "security", scy)
               : !put_string(user, "encryption", "none")) ||
        (f[F_FLOW] && *f[F_FLOW] && !put_string(user, "flow", f[F_FLOW])) ||
        !put_string(stream, "network", or_empty(f[F_TYPE]))) return "out of memory";
    const char *failure = put_transport(stream, f, 1);
    if (failure) return failure;
    const char *security = or_empty(f[F_SECURITY]);
    int insecure = f[F_INSECURE] && !strcmp(f[F_INSECURE], "true");
    if (!strcasecmp(security, "tls") || !strcasecmp(security, "xtls")) {
        const char *name = strcasecmp(security, "tls") ? "xtls" : "tls";
        char key[16];
        snprintf(key, sizeof(key), "%sSettings", name);
        if (!put_string(stream, "security", name) || !put_tls(stream, key, f, insecure)) return "out of memory";
    } else if (!strcasecmp(security, "reality")) {
        json_object *reality = object(stream, "realitySettings");
        if (!reality || !put_string(stream, "security", "reality") ||
            !put_string(reality, "serverName", or_empty(f[F_SNI])) || !put_string(reality, "fingerprint", or_empty(f[F_FP])) ||
            !put(reality, "show", json_object_new_boolean(0)) || !put_string(reality, "publicKey", or_empty(f[F_PBK])) ||
            !put_string(reality, "shortId", or_empty(f[F_SID])) || !put_string(reality, "spiderX", or_empty(f[F_SPX])))
            return "out of memory";
    }
    return NULL;
}

static const char *trojan_outbound(json_object *out, const char *address, int port, const char *password,
                                   char *f[FIELD_COUNT])
{
    json_object *settings = object(out, "settings"), *servers = settings ? array(settings, "servers") : NULL;
    json_object *server = servers ? object(servers, NULL) : NULL, *stream = object(out, "streamSettings");
    json_object *tls = stream ? object(stream, "tlsSettings") : NULL;
    if (!server || !tls || !put_string(out, "protocol", "trojan") || !put_string(server, "address", address) ||
        !put(server, "port", json_object_new_int(port)) || !put_string(server, "password", password) ||
        (f[F_TYPE] && *f[F_TYPE] && !put_string(stream, "network", f[F_TYPE])) ||
        !put_string(stream, "security", "tls") || !put_string(tls, "serverName", or_empty(f[F_SNI])) ||
        !put(tls, "allowInsecure", json_object_new_boolean(f[F_INSECURE] &&
             (!strcmp(f[F_INSECURE], "1") || !strcmp(f[F_INSECURE], "true"))))) return "out of memory";
    return put_transport(stream, f, 0);
}

static const char *shadowsocks_outbound(json_object *out, const char *address, int port, const char *userinfo)
{
    static const char *const ciphers[] = {
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-256-gcm",
        "aes-128-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305", "xchacha20-poly1305",
        "xchacha20-ietf-poly1305", "plain", "none", NULL};
    char *decoded = base64_decode(userinfo, strlen(userinfo));
    char *colon = decoded ? strchr(decoded, ':') : NULL;
    const char *failure = "invalid catalog profile URL";
    if (colon) {
        *colon = '\0';
        for (char *c = decoded; *c; c++) *c = (char)tolower((unsigned char)*c);
        const char *const *cipher = ciphers;
        while (*cipher && strcmp(*cipher, decoded)) cipher++;
        json_object *settings = object(out, "settings"), *servers = settings ? array(settings, "servers") : NULL;
        json_object *server = servers ? object(servers, NULL) : NULL;
        failure = !*cipher ? "unsupported shadowsocks cipher" :
                  server && put_string(out, "protocol", "shadowsocks") && put_string(server, "address", address) &&
                  put(server, "port", json_object_new_int(port)) && put_string(server, "method", decoded) &&
                  put_string(server, "password", colon + 1) ? NULL : "out of memory";
    }
    free(decoded);
    return failure;
}

/* The vmess:// export is base64 of the server object's JSON (V2Ray.ExportToURL). */
static const char *vmess_fields(const char *uri, char *address, int *port, char *f[FIELD_COUNT])
{
    char *raw = base64_decode(uri + 8, strlen(uri + 8));
    json_object *doc = raw ? json_tokener_parse(raw) : NULL;
    free(raw);
    const char *failure = "invalid catalog profile URL";
    if (!json_object_is_type(doc, json_type_object)) goto done;
    for (int i = 0; i < FIELD_COUNT; i++) {
        json_object *value = vmess_keys[i] ? json_object_object_get(doc, vmess_keys[i]) : NULL;
        if (json_object_is_type(value, json_type_string) || json_object_is_type(value, json_type_int))
            f[i] = strdup(json_object_get_string(value));
    }
    json_object *insecure = json_object_object_get(doc, "allowInsecure"), *add = json_object_object_get(doc, "add");
    f[F_INSECURE] = strdup(json_object_get_boolean(insecure) ? "true" : "false");
    *port = json_object_get_int(json_object_object_get(doc, "port"));
    const char *host = json_object_is_type(add, json_type_string) ? json_object_get_string(add) : "";
    if (!*host || strlen(host) > 255 || *port < 1 || *port > 65535) goto done;
    strcpy(address, host);
    /* ParseVmessURL: a host that is really a path, and a missing alterId. */
    if (f[F_HOST] && *f[F_HOST] == '/' && (!f[F_PATH] || !*f[F_PATH])) {
        free(f[F_PATH]);
        f[F_PATH] = f[F_HOST];
        f[F_HOST] = NULL;
    }
    failure = NULL;
done:
    json_object_put(doc);
    return failure;
}

/* ParseVlessURL and the trojan export put a transport's path under its own key. */
static void move_path(char *f[FIELD_COUNT], enum field from)
{
    if (!f[from]) return;
    free(f[F_PATH]);
    f[F_PATH] = f[from];
    f[from] = NULL;
}

static int put_tag(json_object *out) { return put_string(out, "tag", "candidate"); }

static json_object *plain_proxy(const char *scheme, const char *host, int port, const char *user, const char *pass)
{
    int socks = !strcmp(scheme, "socks5");
    json_object *config = json_object_new_object(), *outbounds = config ? array(config, "outbounds") : NULL;
    json_object *out = outbounds ? object(outbounds, NULL) : NULL;
    json_object *settings = out ? object(out, "settings") : NULL, *servers = settings ? array(settings, "servers") : NULL;
    json_object *server = servers ? object(servers, NULL) : NULL;
    if (!server || !put_tag(out) || !put_string(out, "protocol", socks ? "socks" : "http") ||
        !put_string(server, "address", host) || !put(server, "port", json_object_new_int(port))) goto fail;
    if (user) {
        json_object *users = array(server, "users"), *account = users ? object(users, NULL) : NULL;
        if (!account || !put_string(account, "user", user) || !put_string(account, "pass", pass)) goto fail;
    }
    if (strcmp(scheme, "https")) return config;
    json_object *stream = object(out, "streamSettings");
    if (stream && put_string(stream, "security", "tls")) return config;
fail:
    json_object_put(config);
    return NULL;
}

void failover_profile_clear(struct failover_profile *profile)
{
    json_object_put(profile->storage);
    *profile = (struct failover_profile){0};
}

const char *failover_profile_parse(const char *uri, struct failover_profile *profile)
{
    *profile = (struct failover_profile){0};
    if (!uri || !*uri || strlen(uri) > SHARE_URI_LIMIT || !valid_uri_bytes(uri))
        return "invalid catalog profile URL";
    const char *err = "invalid catalog profile URL";
    CURLU *url = curl_url();
    if (!url) return "out of memory";
    char *scheme = NULL, *host = NULL, *port = NULL, *query = NULL, *path = NULL;
    char *user = NULL, *password = NULL, *zone = NULL, *f[FIELD_COUNT] = {0};
    char address[256] = "";
    int port_number = 0;
    const char *display = NULL, *protocol = "vmess";
    if (!strncmp(uri, "vmess://", 8)) {
        if ((err = vmess_fields(uri, address, &port_number, f))) goto done;
        goto build;
    }
    if (curl_url_set(url, CURLUPART_URL, uri, CURLU_NON_SUPPORT_SCHEME | CURLU_PATH_AS_IS) ||
        curl_url_get(url, CURLUPART_SCHEME, &scheme, 0)) goto done;
    protocol = scheme;
    if (strcmp(scheme, "vless") && strcmp(scheme, "trojan") && strcmp(scheme, "ss") &&
        strcmp(scheme, "socks5") && strcmp(scheme, "http") && strcmp(scheme, "https")) {
        /* ssr, trojan-go, tuic, juicity and others run through v2rayA plugins. */
        err = "unsupported catalog protocol";
        goto done;
    }
    if (curl_url_get(url, CURLUPART_HOST, &host, 0) ||
        curl_url_get(url, CURLUPART_PORT, &port, 0) ||
        curl_url_get(url, CURLUPART_ZONEID, &zone, 0) != CURLUE_NO_ZONEID ||
        curl_url_get(url, CURLUPART_PATH, &path, 0) || strcmp(path, "/")) goto done;
    port_number = atoi(port); /* libcurl validates the explicit numeric port. */
    if (!*host || strlen(host) > 255 || port_number < 1 || port_number > 65535) goto done;
    size_t host_length = strlen(host);
    if (host[0] == '[' && host_length > 2 && host[host_length - 1] == ']')
        snprintf(address, sizeof(address), "%.*s", (int)(host_length - 2), host + 1);
    else
        snprintf(address, sizeof(address), "%s", host);

    CURLUcode user_result = curl_url_get(url, CURLUPART_USER, &user, CURLU_URLDECODE);
    CURLUcode password_result = curl_url_get(url, CURLUPART_PASSWORD, &password, CURLU_URLDECODE);
    CURLUcode query_result = curl_url_get(url, CURLUPART_QUERY, &query, 0);
    if ((user_result && user_result != CURLUE_NO_USER) ||
        (password_result && password_result != CURLUE_NO_PASSWORD) ||
        (query_result && query_result != CURLUE_NO_QUERY) ||
        (user && (!*user || strlen(user) > 255 || strchr(user, 127))) ||
        (password && (!*password || strlen(password) > 255 || strchr(password, 127)))) goto done;
    if (!strcmp(scheme, "socks5") || !strcmp(scheme, "http") || !strcmp(scheme, "https")) {
        if (query || (!!user != !!password)) goto done;
        display = scheme;
        profile->storage = plain_proxy(scheme, address, port_number, user, password);
        err = profile->storage ? NULL : "out of memory";
        goto validate;
    }
    if (!user || password) goto done;
    if (!strcmp(scheme, "ss")) {
        if (query) {
            err = "shadowsocks plugins are unsupported";
            goto done;
        }
        goto build;
    }
    if (!parse_query(query, f)) goto done;
    if (!strcmp(scheme, "vless")) {
        /* ParseVlessURL defaults and per-transport keys. */
        const char *net = f[F_TYPE] ? f[F_TYPE] : "";
        if (!strcmp(net, "grpc")) move_path(f, F_SERVICE_NAME);
        if (!strcmp(net, "mkcp") || !strcmp(net, "kcp")) move_path(f, F_SEED);
        if (!*net) { free(f[F_TYPE]); f[F_TYPE] = strdup("tcp"); }
        if (!f[F_HEADER_TYPE] || !*f[F_HEADER_TYPE]) { free(f[F_HEADER_TYPE]); f[F_HEADER_TYPE] = strdup("none"); }
        if (f[F_INSECURE] && strcmp(f[F_INSECURE], "true") && strcmp(f[F_INSECURE], "false")) goto done;
        f[F_ID] = strdup(user);
    } else {
        /* trojan: the export names the stored path by transport. */
        if (f[F_TYPE] && !strcasecmp(f[F_TYPE], "grpc")) move_path(f, F_SERVICE_NAME);
        if (f[F_TYPE] && (!strcasecmp(f[F_TYPE], "mkcp") || !strcasecmp(f[F_TYPE], "kcp"))) move_path(f, F_SEED);
        if (!f[F_SNI] || !*f[F_SNI]) { free(f[F_SNI]); f[F_SNI] = strdup(address); }
    }
build:;
    json_object *config = json_object_new_object(), *outbounds = config ? array(config, "outbounds") : NULL;
    json_object *out = outbounds ? object(outbounds, NULL) : NULL;
    profile->storage = config;
    if (!out || !put_tag(out)) {
        err = "out of memory";
        goto done;
    }
    err = !strcmp(protocol, "ss") ? shadowsocks_outbound(out, address, port_number, user) :
          !strcmp(protocol, "trojan") ? trojan_outbound(out, address, port_number, user, f) :
          v2ray_outbound(out, protocol, address, port_number, f);
validate:
    if (!err) {
        /* The same check as for a running server: one server at this endpoint. */
        char endpoint[270];
        snprintf(endpoint, sizeof(endpoint), strchr(address, ':') ? "[%s]:%d" : "%s:%d", address, port_number);
        struct member member = {.address = endpoint, .display_net = (char *)(display ? display : "")};
        struct outbound outbound = {.name = "candidate", .members = &member, .count = 1};
        err = node_profile_parse(profile->storage, &outbound, &member, &profile->node);
    }
done:
    for (size_t i = 0; i < FIELD_COUNT; ++i) free(f[i]);
    curl_free(scheme);
    curl_free(host);
    curl_free(port);
    curl_free(query);
    curl_free(path);
    curl_free(user);
    curl_free(password);
    curl_free(zone);
    curl_url_cleanup(url);
    if (err) failover_profile_clear(profile);
    return err;
}
