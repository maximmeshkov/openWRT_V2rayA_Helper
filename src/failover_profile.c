#include "failover_profile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define SHARE_URI_LIMIT 16384

enum param { NETWORK, SECURITY, SNI, ALPN, PATH, FINGERPRINT, INSECURE, FLOW, PARAM_COUNT };

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

static int parse_query(const char *query, char *param[PARAM_COUNT])
{
    static const char *keys[PARAM_COUNT] = {
        [NETWORK] = "type", [SECURITY] = "security", [SNI] = "sni", [ALPN] = "alpn",
        [PATH] = "path", [FINGERPRINT] = "fp", [INSECURE] = "allowInsecure", [FLOW] = "flow"
    };
    while (query && *query) {
        const char *end = strchr(query, '&');
        if (!end) end = query + strlen(query);
        const char *eq = memchr(query, '=', (size_t)(end - query));
        if (!eq) return 0;
        size_t pos = 0, key_length = (size_t)(eq - query);
        while (pos < PARAM_COUNT &&
               (strlen(keys[pos]) != key_length || memcmp(query, keys[pos], key_length))) ++pos;
        if (pos == PARAM_COUNT || param[pos]) return 0;
        param[pos] = decode_query(eq + 1, end);
        if (!param[pos]) return 0;
        if (!*end) return 1;
        query = end + 1;
    }
    return 0;
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

static int put_alpn(json_object *tls, const char *text)
{
    json_object *entries = array(tls, "alpn");
    if (!entries) return 0;
    for (;;) {
        const char *end = strchr(text, ',');
        if (!end) end = text + strlen(text);
        const char *start = text, *last = end;
        while (start < last && *start == ' ') ++start;
        while (last > start && last[-1] == ' ') --last;
        if (!put(entries, NULL, json_object_new_string_len(start, (int)(last - start))))
            return 0;
        if (!*end) return 1;
        text = end + 1;
    }
}

static int write_transport(json_object *node, const char *scheme, char *params[PARAM_COUNT])
{
    if (!strcmp(scheme, "vless")) {
        json_object *stream = object(node, "streamSettings");
        if (!stream || !put_string(stream, "network", "xhttp") ||
            !put_string(stream, "security", "tls")) return 0;
        json_object *tls = object(stream, "tlsSettings"), *xhttp = object(stream, "xhttpSettings");
        return tls && xhttp && put_string(tls, "serverName", params[SNI]) &&
              (!params[ALPN] || !*params[ALPN] || put_alpn(tls, params[ALPN])) &&
              (!params[FINGERPRINT] || put_string(tls, "fingerprint", params[FINGERPRINT])) &&
              (!params[INSECURE] || put(tls, "allowInsecure",
                      json_object_new_boolean(!strcmp(params[INSECURE], "true")))) &&
              (!params[PATH] || put_string(xhttp, "path", params[PATH]));
    }
    if (!strcmp(scheme, "https")) {
        json_object *stream = object(node, "streamSettings");
        return stream && put_string(stream, "security", "tls");
    }
    return 1;
}

static json_object *profile_config(const char *scheme, const char *host, int port,
                                  const char *user, const char *pass, char *params[PARAM_COUNT])
{
    int vless = !strcmp(scheme, "vless");
    const char *protocol = vless ? "vless" : !strcmp(scheme, "socks5") ? "socks" : "http";
    json_object *config = json_object_new_object();
    if (!config) return NULL;
    json_object *outbounds = array(config, "outbounds");
    json_object *out = outbounds ? object(outbounds, NULL) : NULL;
    if (!out || !put_string(out, "tag", "candidate") || !put_string(out, "protocol", protocol))
        goto fail;
    json_object *settings = object(out, "settings");
    json_object *servers = settings ? array(settings, vless ? "vnext" : "servers") : NULL;
    json_object *server = servers ? object(servers, NULL) : NULL;
    if (!server || !put_string(server, "address", host) ||
        !put(server, "port", json_object_new_int(port))) goto fail;
    if (user) {
        json_object *users = array(server, "users");
        json_object *account = users ? object(users, NULL) : NULL;
        if (!account || !put_string(account, vless ? "id" : "user", user) ||
            !put_string(account, vless ? "encryption" : "pass", vless ? "none" : pass))
            goto fail;
    }
    if (write_transport(out, scheme, params)) return config;
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
    char *user = NULL, *password = NULL, *zone = NULL;
    char *params[PARAM_COUNT] = {0};
    if (curl_url_set(url, CURLUPART_URL, uri, CURLU_NON_SUPPORT_SCHEME | CURLU_PATH_AS_IS) ||
        curl_url_get(url, CURLUPART_SCHEME, &scheme, 0)) goto done;
    int vless = !strcmp(scheme, "vless");
    if (!vless && strcmp(scheme, "socks5") && strcmp(scheme, "http") && strcmp(scheme, "https")) {
        err = "unsupported catalog protocol";
        goto done;
    }
    if (curl_url_get(url, CURLUPART_HOST, &host, 0) ||
        curl_url_get(url, CURLUPART_PORT, &port, 0) ||
        curl_url_get(url, CURLUPART_ZONEID, &zone, 0) != CURLUE_NO_ZONEID ||
        curl_url_get(url, CURLUPART_PATH, &path, 0) || strcmp(path, "/")) goto done;
    int port_number = atoi(port); /* libcurl validates the explicit numeric port. */
    if (!*host || strlen(host) > 255 || port_number < 1 || port_number > 65535) goto done;

    CURLUcode user_result = curl_url_get(url, CURLUPART_USER, &user, CURLU_URLDECODE);
    CURLUcode password_result = curl_url_get(url, CURLUPART_PASSWORD, &password, CURLU_URLDECODE);
    CURLUcode query_result = curl_url_get(url, CURLUPART_QUERY, &query, 0);
    if ((user_result && user_result != CURLUE_NO_USER) ||
        (password_result && password_result != CURLUE_NO_PASSWORD) ||
        (query_result && query_result != CURLUE_NO_QUERY) ||
        (user && (!*user || strlen(user) > 255 || strchr(user, 127))) ||
        (password && (!*password || strlen(password) > 255 || strchr(password, 127)))) goto done;
    if (vless) {
        if (!user || password || !parse_query(query, params)) goto done;
        if (!params[NETWORK] || strcmp(params[NETWORK], "xhttp") ||
            !params[SECURITY] || strcasecmp(params[SECURITY], "tls") ||
            (params[FLOW] && *params[FLOW])) {
            err = "unsupported catalog VLESS transport";
            goto done;
        }
        /* 2.2.7.4's builder may derive SNI from the source Host when SNI is
         * absent, but the XHTTP share exporter leaves Host out. */
        if (!params[SNI] || !*params[SNI]) {
            err = "catalog XHTTP profile has no explicit TLS server name";
            goto done;
        }
        if (params[INSECURE] && strcmp(params[INSECURE], "true") &&
            strcmp(params[INSECURE], "false")) goto done;
    } else if (query || (!!user != !!password)) {
        goto done;
    }

    /* Adapt the exact exporter fields to the same profile validator used for
     * the running Xray config. Do not retain the URI or use its display label. */
    char endpoint[270], address[256];
    snprintf(endpoint, sizeof(endpoint), "%s:%d", host, port_number);
    size_t host_length = strlen(host);
    if (host[0] == '[' && host_length > 2 && host[host_length - 1] == ']')
        snprintf(address, sizeof(address), "%.*s", (int)(host_length - 2), host + 1);
    else
        snprintf(address, sizeof(address), "%s", host);
    struct member member = {.address = endpoint, .display_net = vless ? "vless(xhttp+tls)" : scheme};
    struct outbound outbound = {.name = "candidate", .members = &member, .count = 1};
    profile->storage = profile_config(scheme, address, port_number, user, password, params);
    if (!profile->storage) {
        err = "out of memory";
        goto done;
    }
    err = node_profile_parse(profile->storage, &outbound, &member, &profile->node);
done:
    for (size_t i = 0; i < PARAM_COUNT; ++i) free(params[i]);
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
