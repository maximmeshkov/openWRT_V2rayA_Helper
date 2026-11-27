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

/* A dual-stack name may resolve first to an address family the router cannot reach. */
enum { MAX_PEERS = 4 };
struct peers {
    struct peer list[MAX_PEERS];
    size_t count;
};

/* Let libcurl resolve the configured host. Returning BAD for every candidate
 * prevents libcurl from opening a TCP connection or sending an HTTP request,
 * and makes it offer the next address. */
static curl_socket_t capture_peer(void *data, curlsocktype purpose,
                                  struct curl_sockaddr *address)
{
    struct peers *p = data;
    if (p->count < MAX_PEERS && purpose == CURLSOCKTYPE_IPCXN &&
        (address->family == AF_INET || address->family == AF_INET6) &&
        address->addrlen <= sizeof(p->list[0].address)) {
        struct peer *next = &p->list[p->count];
        memcpy(&next->address, &address->addr, address->addrlen);
        next->length = address->addrlen;
        for (size_t i = 0; i < p->count; i++)
            if (p->list[i].length == next->length && !memcmp(&p->list[i].address, &next->address, next->length))
                return CURL_SOCKET_BAD;
        p->count++;
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
    struct peers peers = {0};
    CURLU *url = endpoint_url(address);
    CURL *curl = curl_easy_init();
    struct pollfd events[MAX_PEERS];
    size_t sent = 0;
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
        curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &peers))
        goto done;
    CURLcode rc = curl_easy_perform(curl);
    if (!peers.count) {
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
    int64_t started = probe_clock_ms();
    if (started >= deadline) {
        result.state = "timeout";
        result.detail = "dns_timeout";
        goto done;
    }
    const struct peer *sent_to[MAX_PEERS];
    for (size_t i = 0; i < peers.count; i++) {
        const struct peer *peer = &peers.list[i];
        int fd = socket(peer->address.ss_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0) continue;
        if (mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
            close(fd);
            result.detail = "socket_mark_failed";
            goto done;
        }
        if (connect(fd, (const struct sockaddr *)&peer->address, peer->length) ||
            send(fd, packet, sizeof(packet), 0) != (ssize_t)sizeof(packet)) {
            close(fd);
            continue;
        }
        sent_to[sent] = peer;
        events[sent++] = (struct pollfd){.fd = fd, .events = POLLIN};
    }
    result.state = "error";
    result.detail = "quic_unreachable";
    if (!sent) goto done;
    result.state = "timeout";
    result.detail = "quic_no_reply";
    /* The first valid answer from any address counts; an invalid one waits for the others. */
    for (size_t waiting = sent; waiting;) {
        int64_t left = deadline - probe_clock_ms();
        int ready = left > 0 ? poll(events, sent, (int)left) : 0;
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) break;
        for (size_t i = 0; i < sent; i++) {
            if (events[i].fd < 0 || !(events[i].revents & (POLLIN | POLLERR))) continue;
            unsigned char reply[4096];
            ssize_t n = recv(events[i].fd, reply, sizeof(reply), MSG_TRUNC);
            events[i].fd = -events[i].fd - 1;  /* poll ignores negative descriptors */
            waiting--;
            if (n >= 0 && (size_t)n <= sizeof(reply) && valid_reply(reply, (size_t)n, packet)) {
                result.state = "ok";
                result.detail = local_peer(sent_to[i]) ? "local_quic" : "quic";
                result.ms = (long)(probe_clock_ms() - started);
                goto done;
            }
            if (n >= 0) {
                result.state = "error";
                result.detail = "quic_invalid_reply";
            }
        }
    }
done:
    for (size_t i = 0; i < sent; i++) close(events[i].fd < 0 ? -events[i].fd - 1 : events[i].fd);
    if (curl) curl_easy_cleanup(curl);
    if (url) curl_url_cleanup(url);
    result.checked = time(NULL);
    return result;
}
