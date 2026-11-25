#define _GNU_SOURCE
#include "helper.h"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

/* RFC 9000 sections 6.3 and 17.2.1. Each ID is independently unpredictable. */
enum { ID_LEN = 8, HEADER_LEN = 7 + 2 * ID_LEN };
static const unsigned char reserved_version[4] = {0x1a, 0x2a, 0x3a, 0x4a};

struct peer {
    struct sockaddr_storage address;
    socklen_t length;
};

/* Let libcurl resolve the configured host. Returning BAD for every candidate
 * prevents libcurl from opening a TCP connection or sending an HTTP request. */
static curl_socket_t capture_peer(void *data, curlsocktype purpose,
                                  struct curl_sockaddr *address)
{
    struct peer *p = data;
    if (!p->length && purpose == CURLSOCKTYPE_IPCXN &&
        (address->family == AF_INET || address->family == AF_INET6) &&
        address->addrlen <= sizeof(p->address)) {
        memcpy(&p->address, &address->addr, address->addrlen);
        p->length = address->addrlen;
    }
    return CURL_SOCKET_BAD;
}

static int valid_reply(const unsigned char *reply, size_t length,
                       const unsigned char *query)
{
    const unsigned char zero_version[4] = {0};
    if (length < HEADER_LEN + 4 || (length - HEADER_LEN) % 4 ||
        !(reply[0] & 0x80) || memcmp(reply + 1, zero_version, 4) ||
        reply[5] != ID_LEN || reply[6 + ID_LEN] != ID_LEN ||
        memcmp(reply + 6, query + 7 + ID_LEN, ID_LEN) ||
        memcmp(reply + 7 + ID_LEN, query + 6, ID_LEN))
        return 0;
    for (size_t offset = HEADER_LEN; offset < length; offset += 4)
        if (!memcmp(reply + offset, reserved_version, 4) ||
            !memcmp(reply + offset, zero_version, 4))
            return 0;
    return 1;
}

static int local_peer(const struct peer *p)
{
    if (p->address.ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)&p->address;
        return (ntohl(a->sin_addr.s_addr) >> 24) == 127;
    }
    const struct in6_addr *ip = &((const struct sockaddr_in6 *)&p->address)->sin6_addr;
    return IN6_IS_ADDR_LOOPBACK(ip) ||
           (IN6_IS_ADDR_V4MAPPED(ip) && ip->s6_addr[12] == 127);
}

struct measurement probe_quic(const char *address, long timeout_ms, uint32_t mark)
{
    struct measurement result = {.state = "unknown", .detail = "probe_unavailable"};
    struct peer peer = {0};
    CURLU *url = endpoint_url(address);
    CURL *curl = curl_easy_init();
    int fd = -1;
    int64_t deadline = probe_clock_ms() + timeout_ms;
    if (!url) {
        result.detail = "invalid_endpoint";
        goto done;
    }
    if (!curl) goto done;
    if (curl_easy_setopt(curl, CURLOPT_CURLU, url) ||
        curl_easy_setopt(curl, CURLOPT_PROXY, "") ||
        curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L) ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) ||
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms) ||
        curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, capture_peer) ||
        curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &peer))
        goto done;
    CURLcode rc = curl_easy_perform(curl);
    if (!peer.length) {
        if (rc == CURLE_OPERATION_TIMEDOUT) {
            result.state = "timeout";
            result.detail = "dns_timeout";
        } else if (rc == CURLE_COULDNT_RESOLVE_HOST) {
            result.state = "error";
            result.detail = "dns_failed";
        }
        goto done;
    }
    unsigned char packet[1200] = {0xc0}, ids[2 * ID_LEN];
    if (getrandom(ids, sizeof(ids), GRND_NONBLOCK) != (ssize_t)sizeof(ids)) goto done;
    memcpy(packet + 1, reserved_version, 4);
    packet[5] = packet[6 + ID_LEN] = ID_LEN;
    memcpy(packet + 6, ids, ID_LEN);
    memcpy(packet + 7 + ID_LEN, ids + ID_LEN, ID_LEN);
    fd = socket(peer.address.ss_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) goto done;
    if (mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
        result.detail = "socket_mark_failed";
        goto done;
    }
    int64_t started = probe_clock_ms();
    if (started >= deadline) {
        result.state = "timeout";
        result.detail = "dns_timeout";
        goto done;
    }
    result.state = "error";
    result.detail = "quic_unreachable";
    if (connect(fd, (const struct sockaddr *)&peer.address, peer.length) ||
        send(fd, packet, sizeof(packet), 0) != (ssize_t)sizeof(packet))
        goto done;
    struct pollfd event = {.fd = fd, .events = POLLIN};
    int ready;
    do {
        int64_t left = deadline - probe_clock_ms();
        ready = left > 0 ? poll(&event, 1, (int)left) : 0;
    } while (ready < 0 && errno == EINTR);
    if (!ready) {
        result.state = "timeout";
        result.detail = "quic_no_reply";
    } else if (ready > 0) {
        unsigned char reply[4096];
        ssize_t n = recv(fd, reply, sizeof(reply), MSG_TRUNC);
        if (n >= 0) {
            if ((size_t)n <= sizeof(reply) && valid_reply(reply, (size_t)n, packet)) {
                result.state = "ok";
                result.detail = local_peer(&peer) ? "local_quic" : "quic";
                result.ms = (long)(probe_clock_ms() - started);
            } else {
                result.detail = "quic_invalid_reply";
            }
        }
    }
done:
    if (fd >= 0) close(fd);
    if (curl) curl_easy_cleanup(curl);
    if (url) curl_url_cleanup(url);
    result.checked = time(NULL);
    return result;
}
