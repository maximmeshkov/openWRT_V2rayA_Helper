#define _GNU_SOURCE
#include "node_https.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

struct socket_options {
    int fd, borrowed, mark_failed;
    uint32_t mark;
};

static curl_socket_t take_stream(void *opaque, curlsocktype purpose, struct curl_sockaddr *peer)
{
    struct socket_options *options = opaque;
    if (purpose != CURLSOCKTYPE_IPCXN || peer->socktype != SOCK_STREAM || options->borrowed)
        return CURL_SOCKET_BAD;
    options->borrowed = 1;
    return fcntl(options->fd, F_DUPFD_CLOEXEC, 0);
}

static int configure_socket(void *opaque, curl_socket_t fd, curlsocktype purpose)
{
    struct socket_options *options = opaque;
    if (purpose != CURLSOCKTYPE_IPCXN) return CURL_SOCKOPT_ERROR;
    if (options->fd >= 0) return CURL_SOCKOPT_ALREADY_CONNECTED;
    if (options->mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &options->mark, sizeof(options->mark))) {
        options->mark_failed = 1;
        return CURL_SOCKOPT_ERROR;
    }
    return CURL_SOCKOPT_OK;
}

static const char *curl_detail(CURLcode code)
{
    switch (code) {
    case CURLE_OK: return "https_response";
    case CURLE_UNSUPPORTED_PROTOCOL:
    case CURLE_NOT_BUILT_IN: return "unsupported_https_transport";
    case CURLE_OPERATION_TIMEDOUT: return "https_timeout";
    case CURLE_COULDNT_RESOLVE_PROXY:
    case CURLE_COULDNT_RESOLVE_HOST: return "https_dns_error";
    case CURLE_COULDNT_CONNECT: return "https_connect_error";
    case CURLE_SSL_CONNECT_ERROR:
    case CURLE_PEER_FAILED_VERIFICATION:
    case CURLE_SSL_CACERT_BADFILE: return "https_tls_error";
    case CURLE_PROXY:
    case CURLE_LOGIN_DENIED: return "https_proxy_error";
    default: return "https_request_failed";
    }
}

static CURLU *proxy_url(const struct node_https_proxy *proxy)
{
    if (!proxy || !proxy->scheme || !proxy->address || !*proxy->address ||
        proxy->port < 1 || proxy->port > 65535 ||
        (strcmp(proxy->scheme, "socks5h") && strcmp(proxy->scheme, "socks4a") &&
         strcmp(proxy->scheme, "http") && strcmp(proxy->scheme, "https"))) return NULL;

    CURLU *url = curl_url();
    char port[6], ipv6[INET6_ADDRSTRLEN + 2];
    struct in6_addr addr6;
    const char *host = proxy->address;
    if (inet_pton(AF_INET6, host, &addr6) == 1) {
        snprintf(ipv6, sizeof(ipv6), "[%s]", host);
        host = ipv6;
    }
    snprintf(port, sizeof(port), "%d", proxy->port);
    if (url && !curl_url_set(url, CURLUPART_SCHEME, proxy->scheme, CURLU_NON_SUPPORT_SCHEME) &&
        !curl_url_set(url, CURLUPART_HOST, host, 0) && !curl_url_set(url, CURLUPART_PORT, port, 0))
        return url;
    if (url) curl_url_cleanup(url);
    return NULL;
}

static size_t discard_body(char *data, size_t size, size_t count, void *opaque)
{
    size_t *received = opaque;
    (void)data;
    if (size && count > (65536 - *received) / size) return 0;
    *received += size * count;
    return size * count;
}

static int run_request(struct socket_options *options, const struct node_https_proxy *proxy,
                       const char *url, long timeout_ms, long expected_code,
                       struct node_https_result *result)
{
    if (!result) return 0;
    *result = (struct node_https_result){.detail = "https_invalid_config"};
    if (!url || strncasecmp(url, "https://", 8) || timeout_ms <= 0 ||
        expected_code < 100 || expected_code > 599 || (options->fd < 0 && !proxy)) return 0;

    CURLU *target = curl_url(), *upstream = NULL;
    CURL *curl = curl_easy_init();
    struct curl_slist *connect_to = NULL;
    char *proxy_string = NULL;
    const char *ca = getenv("SSL_CERT_FILE");
    size_t received = 0;
    int ok = 0;
    if (!curl || !target || curl_url_set(target, CURLUPART_URL, url, CURLU_DISALLOW_USER)) goto done;
    if (curl_easy_setopt(curl, CURLOPT_CURLU, target) ||
        (ca && *ca && curl_easy_setopt(curl, CURLOPT_CAINFO, ca)) ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) ||
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms) ||
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L) ||
        curl_easy_setopt(curl, CURLOPT_NOPROXY, "") ||
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L) ||
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L) ||
        curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, configure_socket) ||
        curl_easy_setopt(curl, CURLOPT_SOCKOPTDATA, options) ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_body) ||
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &received)) goto done;

    if (proxy) {
        if (proxy->scheme && !strcmp(proxy->scheme, "https") &&
            !(curl_version_info(CURLVERSION_NOW)->features & CURL_VERSION_HTTPS_PROXY)) {
            result->detail = "unsupported_https_transport";
            goto done;
        }
        upstream = proxy_url(proxy);
        if (!upstream || curl_url_get(upstream, CURLUPART_URL, &proxy_string, 0) ||
            curl_easy_setopt(curl, CURLOPT_PROXY, proxy_string) ||
            (ca && *ca && !strcmp(proxy->scheme, "https") && curl_easy_setopt(curl, CURLOPT_PROXY_CAINFO, ca)) ||
            curl_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYPEER, 1L) ||
            curl_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYHOST, 2L) ||
            (proxy->username && *proxy->username && curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, proxy->username)) ||
            (proxy->password && *proxy->password && curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, proxy->password))) goto done;
    } else {
        /* Only the supplied fd is ever used. A numeric connect target suppresses
         * local DNS while the original URL continues to govern SNI and TLS. */
        connect_to = curl_slist_append(NULL, "::127.0.0.1:1");
        if (!connect_to || curl_easy_setopt(curl, CURLOPT_CONNECT_TO, connect_to) ||
            curl_easy_setopt(curl, CURLOPT_PROXY, "") ||
            curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, take_stream) ||
            curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, options)) goto done;
    }

    CURLcode rc = curl_easy_perform(curl);
    curl_off_t elapsed_us = 0;
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME_T, &elapsed_us);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result->http_code);
    result->ms = (long)((elapsed_us + 500) / 1000);
    result->detail = options->mark_failed ? "https_mark_error" : curl_detail(rc);
    if (rc == CURLE_OK) {
        ok = result->http_code == expected_code;
        if (!ok) result->detail = "https_http_error";
    }
done:
    if (curl) curl_easy_cleanup(curl);
    if (target) curl_url_cleanup(target);
    if (upstream) curl_url_cleanup(upstream);
    curl_free(proxy_string);
    curl_slist_free_all(connect_to);
    return ok;
}

int node_https_proxy(const struct node_https_proxy *proxy, const char *url, long timeout_ms,
                     uint32_t mark, long expected_code, struct node_https_result *result)
{
    struct socket_options options = {.fd = -1, .mark = mark};
    return run_request(&options, proxy, url, timeout_ms, expected_code, result);
}

int node_https_fd(int fd, const char *url, long timeout_ms, long expected_code,
                  struct node_https_result *result)
{
    struct socket_options options = {.fd = fd};
    return run_request(&options, NULL, url, timeout_ms, expected_code, result);
}
