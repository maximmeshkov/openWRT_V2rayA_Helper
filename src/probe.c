#define _GNU_SOURCE
#include "helper.h"
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

struct probe {
    struct member *member;
    long timeout;
    uint32_t mark;
    int mark_failed;
};

static int mark_socket(void *data, curl_socket_t fd, curlsocktype purpose)
{
    struct probe *p = data;
    if (purpose == CURLSOCKTYPE_IPCXN && p->mark &&
        setsockopt(fd, SOL_SOCKET, SO_MARK, &p->mark, sizeof(p->mark)) < 0) {
        p->mark_failed = 1;
        return CURL_SOCKOPT_ERROR;
    }
    return CURL_SOCKOPT_OK;
}

/* The API supplies a host:port, never an arbitrary URL. */
CURLU *endpoint_url(const char *address)
{
    CURLU *url = NULL;
    char *text = NULL, *port = NULL;
    if (!address || !*address || strpbrk(address, "/@?#\\ \t\n\r") ||
        strchr(address, '%') || !strchr(address, ':'))
        return NULL;
    if (asprintf(&text, "http://%s", address) < 0)
        return NULL;
    url = curl_url();
    if (url && (curl_url_set(url, CURLUPART_URL, text, 0) ||
                curl_url_get(url, CURLUPART_PORT, &port, 0) ||
                !port || atoi(port) <= 0)) {
        curl_url_cleanup(url);
        url = NULL;
    }
    curl_free(port);
    free(text);
    return url;
}

int64_t probe_clock_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int is_loopback(const char *ip)
{
    struct in_addr v4;
    struct in6_addr v6;
    return ip && ((inet_pton(AF_INET, ip, &v4) && (ntohl(v4.s_addr) >> 24) == 127) ||
                  (inet_pton(AF_INET6, ip, &v6) && (IN6_IS_ADDR_LOOPBACK(&v6) ||
                   (IN6_IS_ADDR_V4MAPPED(&v6) && v6.s6_addr[12] == 127))));
}

static void probe_one(struct probe *p)
{
    if (!strcmp(p->member->transport, "quic")) {
        p->member->server = probe_quic(p->member->address, p->timeout, p->mark);
        return;
    }
    struct measurement result = {.state = "unknown", .detail = "probe_unavailable"};
    CURLU *url = endpoint_url(p->member->address);
    CURL *c = curl_easy_init();
    if (!url) {
        result.detail = "invalid_endpoint";
    } else if (c) {
        CURLcode rc;
        char *ip = NULL;
        long os_error = 0;
        curl_off_t connected = 0, resolved = 0;
        if (curl_easy_setopt(c, CURLOPT_CURLU, url) ||
            curl_easy_setopt(c, CURLOPT_PROXY, "") ||
            curl_easy_setopt(c, CURLOPT_CONNECT_ONLY, 1L) ||
            curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L) ||
            curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, p->timeout) ||
            curl_easy_setopt(c, CURLOPT_SOCKOPTFUNCTION, mark_socket) ||
            curl_easy_setopt(c, CURLOPT_SOCKOPTDATA, p))
            goto done;
        rc = curl_easy_perform(c);
        curl_easy_getinfo(c, CURLINFO_OS_ERRNO, &os_error);
        if (rc == CURLE_OK) {
            curl_easy_getinfo(c, CURLINFO_NAMELOOKUP_TIME_T, &resolved);
            curl_easy_getinfo(c, CURLINFO_CONNECT_TIME_T, &connected);
            curl_easy_getinfo(c, CURLINFO_PRIMARY_IP, &ip);
            result.state = "ok";
            result.detail = is_loopback(ip) ? "local_tcp" : "tcp";
            result.ms = connected >= resolved ? (long)((connected - resolved + 500) / 1000) : 0;
        } else if (p->mark_failed) {
            result.detail = "socket_mark_failed";
        } else if (rc == CURLE_OPERATION_TIMEDOUT) {
            result.state = "timeout";
            result.detail = "dns_or_connect_timeout";
        } else if (rc == CURLE_COULDNT_RESOLVE_HOST) {
            result.state = "error";
            result.detail = "dns_failed";
        } else if (rc == CURLE_COULDNT_CONNECT && os_error == ECONNREFUSED) {
            result.state = "refused";
            result.detail = "tcp_refused";
        } else {
            result.state = "error";
            result.detail = "connect_failed";
        }
    }
done:
    result.checked = time(NULL);
    p->member->server = result;
    if (c) curl_easy_cleanup(c);
    if (url) curl_url_cleanup(url);
}

/* A resolver may block beyond libcurl's timeout even on threaded-resolver
 * builds. Fork our workers from the main loop and bound the whole batch.
 * Both measurement strings are static literals in the same executable mapping
 * inherited by fork. No child-owned heap pointer travels in the reply. */
void probe_members(struct probe_job *jobs, size_t count, long timeout_ms, uint32_t mark,
                   const struct https_options *https, json_object *config)
{
    struct reply { size_t slot; struct measurement sample; long code; int standard_tls; };
    int channel[2];
    pid_t workers[16] = {0};
    int received[16] = {0};
    if (!count) return;
    for (size_t i = 0; i < count; ++i) {
        struct member *m = jobs[i].member;
        struct measurement *sample = https ? &m->https : &m->server;
        if (https) { m->http_code = 0; m->standard_tls = 0; }
        *sample = (struct measurement) {
            .state = "unknown", .detail = "probe_unavailable", .checked = time(NULL)
        };
    }
    if (pipe2(channel, O_CLOEXEC) < 0) return;
    const pid_t parent = getpid();
    /* Give a worker time to return its specific socket timeout to the parent. */
    const int64_t deadline = probe_clock_ms() + timeout_ms + 50;
    for (size_t i = 0; i < count; ++i) {
        pid_t pid = fork();
        if (pid == 0) {
            close(channel[0]);
            if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != parent) _exit(1);
            struct member *m = jobs[i].member;
            if (https) {
                probe_node(jobs[i], config, https, mark);
            } else {
                struct probe p = {.member = m, .timeout = timeout_ms, .mark = mark};
                probe_one(&p);
            }
            struct reply r = {.slot = i, .sample = https ? m->https : m->server,
                              .code = m->http_code, .standard_tls = m->standard_tls};
            /* One write below PIPE_BUF; concurrent workers cannot interleave. */
            ssize_t n;
            do { n = write(channel[1], &r, sizeof(r)); } while (n < 0 && errno == EINTR);
            _exit(n == (ssize_t)sizeof(r) ? 0 : 1);
        }
        workers[i] = pid;
    }
    close(channel[1]);
    struct pollfd event = {.fd = channel[0], .events = POLLIN};
    int timed_out = 0;
    for (;;) {
        int64_t left = deadline - probe_clock_ms();
        int ready = left > 0 ? poll(&event, 1, (int)left) : 0;
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) {
            timed_out = !ready;
            break;
        }
        struct reply r;
        ssize_t n = read(channel[0], &r, sizeof(r));
        if (n < 0 && errno == EINTR) continue;
        if (n != (ssize_t)sizeof(r)) break;
        if (r.slot < count) {
            struct member *m = jobs[r.slot].member;
            if (https) {
                m->https = r.sample;
                m->http_code = r.code;
                m->standard_tls = r.standard_tls;
            } else m->server = r.sample;
            received[r.slot] = 1;
        }
    }
    close(channel[0]);
    for (size_t i = 0; i < count; ++i) {
        if (workers[i] <= 0) continue;
        if (!received[i]) {
            kill(workers[i], SIGKILL);
            if (timed_out) {
                struct member *m = jobs[i].member;
                struct measurement *sample = https ? &m->https : &m->server;
                *sample = (struct measurement) {
                    .state = "timeout", .detail = "dns_or_probe_timeout", .checked = time(NULL)
                };
            }
        }
        while (waitpid(workers[i], NULL, 0) < 0 && errno == EINTR) {}
    }
}
