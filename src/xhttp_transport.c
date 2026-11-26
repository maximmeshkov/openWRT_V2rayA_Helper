#define _GNU_SOURCE
#include "xhttp_transport.h"
#include "node_profile.h"
#include "helper.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>

/* Wire format: Xray-core v25.10.15, transport/internet/splithttp. A long
 * download and the uploads are multiplexed without opening a TCP listener. */
enum mode { PACKET_UP, STREAM_UP, STREAM_ONE };
struct relay {
    const struct node_profile *ep;
    int fd, paused, eof, header_bytes, addon_bytes;
    uint32_t mark;
    const unsigned char *prefix;
    size_t prefix_left;
    int64_t deadline;
    enum mode mode;
    char *tls_origin, *http_origin, *session_path, *connect_to;
    const char *query;
    struct curl_slist *connect, *headers, *upload_headers;
    CURLM *multi;
};

static int random_bytes(void *bytes, size_t size)
{
    unsigned char *p = bytes;
    while (size) {
        ssize_t n = getrandom(p, size, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        p += n;
        size -= (size_t)n;
    }
    return 1;
}

static int hostname(const char *s, char *out, size_t cap)
{
    if (!s || !*s || strlen(s) > 253) return 0;
    struct in6_addr v6;
    if (inet_pton(AF_INET6, s, &v6) == 1)
        return snprintf(out, cap, "[%s]", s) < (int)cap;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
        if (!isalnum(*p) && *p != '.' && *p != '-' && *p != '_') return 0;
    return snprintf(out, cap, "%s", s) < (int)cap;
}

static int add_header(struct curl_slist **headers, const char *s)
{
    struct curl_slist *next = curl_slist_append(*headers, s);
    if (!next) return 0;
    *headers = next;
    return 1;
}

static int make_session_path(struct relay *r)
{
    const char *path = r->ep->path ? r->ep->path : "";
    const size_t n = strcspn(path, "?");
    if (strlen(path) > 4096) return 0;
    r->query = path + n;
    for (const unsigned char *p = (const unsigned char *)r->query; *p; ++p)
        if (*p <= 32 || *p >= 127 || *p == '#') return 0;
    char *dest = r->session_path = malloc(3*n + 40);
    if (!dest) return 0;
    if (!n || *path != '/') *dest++ = '/';
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)path[i];
        if ((c < 128 && isalnum(c)) || strchr("/-._~:$&+,;=@", c)) *dest++ = (char)c;
        else {
            *dest++ = '%';
            *dest++ = (char)toupper(hex[c >> 4]);
            *dest++ = (char)toupper(hex[c & 15]);
        }
    }
    if (dest[-1] != '/') *dest++ = '/';
    if (r->mode != STREAM_ONE) {
        unsigned char id[16];
        if (!random_bytes(id, sizeof(id))) return 0;
        id[6] = (id[6] & 15) | 0x40;
        id[8] = (id[8] & 63) | 0x80;
        for (size_t i = 0; i < sizeof(id); ++i) {
            if (i == 4 || i == 6 || i == 8 || i == 10) *dest++ = '-';
            *dest++ = hex[id[i] >> 4];
            *dest++ = hex[id[i] & 15];
        }
    }
    *dest = 0;
    return 1;
}

static int setup_address(struct relay *r)
{
    const struct node_profile *ep = r->ep;
    char physical[260], name[260], authority_header[300];
    if (!hostname(ep->host, physical, sizeof(physical)) ||
        !hostname(ep->sni && *ep->sni ? ep->sni : ep->host, name, sizeof(name)) ||
        ep->port <= 0 || ep->port > 65535) return 0;
    const char *authority = ep->authority && *ep->authority ? ep->authority : name;
    if (!*authority || strlen(authority) > 280) return 0;
    for (const unsigned char *p = (const unsigned char *)authority; *p; ++p)
        if (!isalnum(*p) && !strchr(".-_[]:", *p)) return 0;
    snprintf(authority_header, sizeof(authority_header), "Host: %s", authority);
    if (asprintf(&r->tls_origin, "https://%s", name) < 0 ||
        asprintf(&r->http_origin, "https://%s", authority) < 0 ||
        asprintf(&r->connect_to, "::%s:%d", physical, ep->port) < 0) return 0;
    r->connect = curl_slist_append(NULL, r->connect_to);
    return r->connect && add_header(&r->headers, authority_header) &&
           add_header(&r->upload_headers, authority_header) &&
           add_header(&r->upload_headers, "Expect:") &&
           add_header(&r->upload_headers, r->mode == PACKET_UP ? "Content-Type:" : "Content-Type: application/grpc") &&
           make_session_path(r);
}

static int mark_fd(void *ctx, curl_socket_t fd, curlsocktype purpose)
{
    struct relay *r = ctx;
    if (purpose == CURLSOCKTYPE_IPCXN && r->mark &&
        setsockopt(fd, SOL_SOCKET, SO_MARK, &r->mark, sizeof(r->mark)) < 0)
        return CURL_SOCKOPT_ERROR;
    return CURL_SOCKOPT_OK;
}

static size_t check_status(char *buf, size_t size, size_t count, void *ctx)
{
    const struct relay *r = ctx;
    size_t n = size * count;
    if (n < 5 || memcmp(buf, "HTTP/", 5)) return n;
    const char *expected = r->ep->http_version == 2 ? "HTTP/2 " : "HTTP/1.1 ";
    size_t k = strlen(expected);
    if (n < k + 4 || memcmp(buf, expected, k) || memcmp(buf + k, "200", 3) ||
        (buf[k+3] != ' ' && buf[k+3] != '\r')) return 0;
    return n;
}

static size_t discard(char *buf, size_t size, size_t count, void *ctx)
{
    (void)buf; (void)ctx;
    return size * count;
}

static size_t downstream(char *buf, size_t size, size_t count, void *ctx)
{
    struct relay *r = ctx;
    size_t n = size * count, i = 0;
    /* VLESS v0 response: first byte version, then addon length, then addon. */
    while (i < n && r->header_bytes < 2) {
        unsigned char c = (unsigned char)buf[i++];
        if (!r->header_bytes && c) return 0;
        if (r->header_bytes++) r->addon_bytes = c;
    }
    while (i < n && r->addon_bytes) { ++i; --r->addon_bytes; }
    while (i < n) {
        ssize_t sent = send(r->fd, buf + i, n - i, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent > 0) { i += (size_t)sent; continue; }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd fd = {.fd = r->fd, .events = POLLOUT};
            int64_t left = r->deadline - probe_clock_ms();
            int ready = left > 0 ? poll(&fd, 1, (int)left) : 0;
            if (ready > 0 || (ready < 0 && errno == EINTR)) continue;
        }
        return 0;
    }
    return n;
}

static size_t upstream(char *buf, size_t size, size_t count, void *ctx)
{
    struct relay *r = ctx;
    size_t cap = size * count;
    if (r->prefix_left && (r->mode != PACKET_UP || r->prefix_left >= cap)) {
        size_t n = cap < r->prefix_left ? cap : r->prefix_left;
        memcpy(buf, r->prefix, n);
        r->prefix += n;
        r->prefix_left -= n;
        return n;
    }
    ssize_t n;
    /* The TLS client supplies a ClientHello first. In packet-up send it with
     * the VLESS header, avoiding a separate POST and inter-POST delay. */
    do {
        n = recv(r->fd, buf + r->prefix_left, cap - r->prefix_left, MSG_DONTWAIT);
    } while (n < 0 && errno == EINTR);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        r->paused = 1;
        return CURL_READFUNC_PAUSE;
    }
    if (n < 0) return CURL_READFUNC_ABORT;
    if (!n) r->eof = 1;
    if (n && r->prefix_left) {
        memcpy(buf, r->prefix, r->prefix_left);
        n += (ssize_t)r->prefix_left;
        r->prefix_left = 0;
    }
    return (size_t)n;
}

/* A download GET and a streaming upload may be alive together. Packet POSTs
 * have a known length, and each is acknowledged before reusing its buffer. */
static CURL *request(struct relay *r, int upload, int download, unsigned int seq,
                     const char *packet, size_t packet_len)
{
    CURL *c = NULL;
    char suffix[32] = "", padding[1001], *url = NULL, *referer = NULL;
    unsigned short random;
    const char *ca = getenv("SSL_CERT_FILE");
    if (!random_bytes(&random, sizeof(random))) return NULL;
    size_t n = 100 + random % 901;
    memset(padding, 'X', n);
    padding[n] = 0;
    if (packet) snprintf(suffix, sizeof(suffix), "/%u", seq);
    if (asprintf(&url, "%s%s%s%s", r->tls_origin, r->session_path, suffix, r->query) < 0 ||
        asprintf(&referer, "%s%s%s?x_padding=%s", r->http_origin, r->session_path,
                 suffix, padding) < 0) goto done;
    c = curl_easy_init();
    if (!c) goto done;
    if (curl_easy_setopt(c, CURLOPT_URL, url) ||
        curl_easy_setopt(c, CURLOPT_PATH_AS_IS, 1L) ||
        curl_easy_setopt(c, CURLOPT_PROXY, "") ||
        curl_easy_setopt(c, CURLOPT_CONNECT_TO, r->connect) ||
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, upload ? r->upload_headers : r->headers) ||
        curl_easy_setopt(c, CURLOPT_REFERER, referer) ||
        curl_easy_setopt(c, CURLOPT_HTTP_VERSION, r->ep->http_version == 2
                         ? (long)CURL_HTTP_VERSION_2TLS : (long)CURL_HTTP_VERSION_1_1) ||
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, r->ep->allow_insecure ? 0L : 1L) ||
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, r->ep->allow_insecure ? 0L : 2L) ||
        (ca && *ca && curl_easy_setopt(c, CURLOPT_CAINFO, ca)) ||
        curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L) ||
        curl_easy_setopt(c, CURLOPT_SOCKOPTFUNCTION, mark_fd) ||
        curl_easy_setopt(c, CURLOPT_SOCKOPTDATA, r) ||
        curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, check_status) ||
        curl_easy_setopt(c, CURLOPT_HEADERDATA, r) ||
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, download ? downstream : discard) ||
        curl_easy_setopt(c, CURLOPT_WRITEDATA, r) ||
        (upload && curl_easy_setopt(c, CURLOPT_POST, 1L)) ||
        (packet && (curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)packet_len) ||
                    curl_easy_setopt(c, CURLOPT_POSTFIELDS, packet))) ||
        (upload && !packet && (curl_easy_setopt(c, CURLOPT_READFUNCTION, upstream) ||
                               curl_easy_setopt(c, CURLOPT_READDATA, r))) ||
        curl_multi_add_handle(r->multi, c) != CURLM_OK) {
        curl_easy_cleanup(c);
        c = NULL;
    }
done:
    free(url);
    free(referer);
    return c;
}

static void finish_request(struct relay *r, CURL **handle)
{
    if (!*handle) return;
    curl_multi_remove_handle(r->multi, *handle);
    curl_easy_cleanup(*handle);
    *handle = NULL;
}

static int run(struct relay *r)
{
    CURL *down = request(r, r->mode == STREAM_ONE, 1, 0, NULL, 0), *up = NULL;
    char packet[8192];
    unsigned int seq = 0;
    int64_t next_post = 0;
    int result = 1;
    if (!down) goto done;
    if (r->mode == STREAM_UP && !(up = request(r, 1, 0, 0, NULL, 0))) goto done;
    for (;;) {
        int64_t now = probe_clock_ms();
        if (now >= r->deadline) break;
        if (r->mode == PACKET_UP && !up && !r->eof && now >= next_post) {
            size_t n = upstream(packet, 1, sizeof(packet), r);
            if (n == CURL_READFUNC_ABORT) break;
            if (n && n != CURL_READFUNC_PAUSE) {
                if (!(up = request(r, 1, 0, seq++, packet, n))) break;
                next_post = now + 30; /* Xray default scMinPostsIntervalMs */
            }
        }
        int running;
        if (curl_multi_perform(r->multi, &running) != CURLM_OK) break;
        int remaining;
        CURLMsg *msg;
        while ((msg = curl_multi_info_read(r->multi, &remaining))) {
            if (msg->msg != CURLMSG_DONE) continue;
            if (msg->data.result != CURLE_OK) goto done;
            if (msg->easy_handle == down) {
                result = r->header_bytes == 2 && !r->addon_bytes ? 0 : 1;
                goto done;
            }
            if (r->mode == STREAM_UP && !r->eof) goto done;
            finish_request(r, &up);
        }
        now = probe_clock_ms();
        long wait = (long)(r->deadline - now);
        if (wait <= 0) break;
        int watch = !r->eof && (r->mode == PACKET_UP ? !up : r->paused);
        if (r->mode == PACKET_UP && watch && next_post > now) {
            watch = 0;
            if (next_post - now < wait) wait = (long)(next_post - now);
        }
        struct curl_waitfd local = {.fd = r->fd, .events = CURL_WAIT_POLLIN};
        if (curl_multi_poll(r->multi, watch ? &local : NULL, watch ? 1 : 0,
                            (int)wait, NULL) != CURLM_OK) break;
        if (watch && local.revents && r->paused && r->mode != PACKET_UP) {
            r->paused = 0;
            if (curl_easy_pause(r->mode == STREAM_ONE ? down : up, CURLPAUSE_CONT)) break;
        }
    }
done:
    finish_request(r, &up);
    finish_request(r, &down);
    return result;
}

int xhttp_relay(const struct node_profile *ep, const unsigned char *prefix,
                size_t prefix_len, int stream_fd, uint32_t mark, long timeout_ms)
{
    if (!ep || !prefix || !prefix_len || timeout_ms <= 0 || timeout_ms > 600000) return 2;
    const char *mode = ep->mode ? ep->mode : "";
    struct relay r = {.ep = ep, .fd = stream_fd, .mark = mark, .prefix = prefix,
        .prefix_left = prefix_len, .deadline = probe_clock_ms() + timeout_ms};
    if (!*mode || !strcmp(mode, "auto") || !strcmp(mode, "packet-up")) r.mode = PACKET_UP;
    else if (!strcmp(mode, "stream-up")) r.mode = STREAM_UP;
    else if (!strcmp(mode, "stream-one")) r.mode = STREAM_ONE;
    else return 2;
    if (ep->http_version != 1 && ep->http_version != 2) return 2;
    if (ep->http_version == 1 && r.mode != PACKET_UP) return 2;
    if (ep->http_version == 2 && !(curl_version_info(CURLVERSION_NOW)->features & CURL_VERSION_HTTP2))
        return 2;
    int rc = 1;
    r.multi = curl_multi_init();
    if (r.multi && setup_address(&r)) rc = run(&r);
    if (r.multi) curl_multi_cleanup(r.multi);
    curl_slist_free_all(r.connect);
    curl_slist_free_all(r.headers);
    curl_slist_free_all(r.upload_headers);
    free(r.connect_to);
    free(r.tls_origin);
    free(r.http_origin);
    free(r.session_path);
    return rc;
}
