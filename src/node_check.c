#define _GNU_SOURCE
#include "helper.h"
#include "node_profile.h"
#include "node_https.h"
#include "xhttp_transport.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* Version, UUID, empty addons, TCP command, big-endian port and address. */
static size_t vless_request(unsigned char *buf, const struct node_profile *p,
                            const struct https_options *target)
{
    size_t n = 1;
    buf[0] = 0;
    for (const char *s = p->uuid; *s;) {
        if (*s == '-') { ++s; continue; }
        char octet[] = {s[0], s[1], 0};
        buf[n++] = (unsigned char)strtoul(octet, NULL, 16);
        s += 2;
    }
    buf[n++] = 0;
    buf[n++] = 1;
    buf[n++] = (unsigned char)(target->port >> 8);
    buf[n++] = (unsigned char)target->port;
    if (inet_pton(AF_INET, target->host, buf+n+1) == 1) {
        buf[n] = 1;
        return n+5;
    }
    size_t len = strlen(target->host);
    if (target->host[0] == '[') {
        char v6[sizeof(target->host)];
        memcpy(v6, target->host+1, len-2);
        v6[len-2] = 0;
        if (inet_pton(AF_INET6, v6, buf+n+1) != 1) return 0;
        buf[n] = 3;
        return n+17;
    }
    buf[n++] = 2;
    buf[n++] = (unsigned char)len;
    memcpy(buf+n, target->host, len);
    return n+len;
}

static int via_xhttp(struct node_profile *p, const struct https_options *opt, uint32_t mark,
                     struct node_https_result *result)
{
    enum { WORKER_SETUP_FAILED = XHTTP_STREAM_FAILED + 1 };
    unsigned char prefix[280];
    size_t len = vless_request(prefix, p, opt);
    long timeout_ms = opt->timeout * 1000;
    int64_t deadline = probe_clock_ms() + timeout_ms;
    int fd[2], report[2];
    if (!len || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fd)) return 0;
    if (pipe2(report, O_NONBLOCK | O_CLOEXEC)) {
        close(fd[0]);
        close(fd[1]);
        return 0;
    }
    pid_t parent = getpid(), child = fork();
    if (!child) {
        close(fd[0]);
        close(report[0]);
        unsigned char rc = WORKER_SETUP_FAILED;
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) == 0 && getppid() == parent)
            rc = xhttp_relay(p, prefix, len, fd[1], mark, timeout_ms);
        /* Publish the relay outcome before closing its copy of the byte stream.
         * The inner TLS client can then distinguish EOF caused by this relay. */
        ssize_t written;
        do { written = write(report[1], &rc, 1); } while (written < 0 && errno == EINTR);
        _exit(rc);
    }
    close(fd[1]);
    close(report[1]);
    int ok = child > 0 && node_https_fd(fd[0], opt->url, timeout_ms, opt->code, result);
    if (child > 0 && !ok && !result->http_code) {
        unsigned char rc;
        ssize_t n;
        do { n = read(report[0], &rc, 1); } while (n < 0 && errno == EINTR);
        if (n == 1) {
            if (rc == XHTTP_SESSION_FAILED)
                result->detail = probe_clock_ms() >= deadline ? "https_timeout" : "xhttp_session_failed";
            else if (rc == XHTTP_UNSUPPORTED) result->detail = "unsupported_xhttp_transport";
            else if (rc == WORKER_SETUP_FAILED) result->detail = "probe_unavailable";
        }
    }
    close(report[0]);
    close(fd[0]);
    if (child > 0) {
        pid_t done;
        do { done = waitpid(child, NULL, WNOHANG); } while (done < 0 && errno == EINTR);
        if (done == 0) {
            kill(child, SIGKILL);
            while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        }
    }
    return ok;
}

struct measurement probe_https_profile(struct node_profile *p, const struct https_options *opt,
                                       uint32_t mark, long *http_code)
{
    struct measurement m = {.state = "unsupported", .checked = time(NULL)};
    *http_code = 0;
    uint32_t socket_mark = p->has_mark ? p->mark : mark;
    struct node_https_result r = {.detail = "probe_unavailable"};
    int ok;
    if (p->kind == NODE_VLESS_XHTTP) {
        if (p->http_version == 2 && !(curl_version_info(CURLVERSION_NOW)->features & CURL_VERSION_HTTP2)) {
            m.detail = "HTTP/2 unavailable in libcurl";
            return m;
        }
        ok = via_xhttp(p, opt, socket_mark, &r);
    } else {
        const char *scheme = p->kind == NODE_SOCKS5 ? "socks5h" : p->kind == NODE_HTTP ? "http" : "https";
        struct node_https_proxy proxy = {scheme, p->host, p->username, p->password, p->port};
        ok = node_https_proxy(&proxy, opt->url, opt->timeout*1000, socket_mark, opt->code, &r);
    }
    m.checked = time(NULL);
    m.state = ok ? "ok" : "error";
    m.detail = r.detail;
    if (!ok && r.detail && !strncmp(r.detail, "unsupported", 11)) m.state = "unsupported";
    m.ms = r.ms;
    *http_code = r.http_code;
    return m;
}

void probe_node(struct probe_job job, json_object *config, const struct https_options *opt,
                uint32_t mark)
{
    struct node_profile p;
    const char *reason = config ? node_profile_parse(config, job.out, job.member, &p) : "config_unavailable";
    if (reason) {
        job.member->https = (struct measurement){.state = "unsupported", .detail = reason, .checked = time(NULL)};
        return;
    }
    job.member->standard_tls = p.kind == NODE_VLESS_XHTTP && *p.fingerprint != 0;
    job.member->https = probe_https_profile(&p, opt, mark, &job.member->http_code);
}
