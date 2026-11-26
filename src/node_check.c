#define _GNU_SOURCE
#include "helper.h"
#include "node_profile.h"
#include "node_https.h"
#include "xhttp_transport.h"
#include <arpa/inet.h>
#include <errno.h>
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
    unsigned char prefix[280];
    size_t len = vless_request(prefix, p, opt);
    int fd[2];
    if (!len || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fd)) return 0;
    pid_t parent = getpid(), child = fork();
    if (!child) {
        close(fd[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != parent) _exit(1);
        _exit(xhttp_relay(p, prefix, len, fd[1], mark, opt->timeout*1000));
    }
    close(fd[1]);
    int ok = child > 0 && node_https_fd(fd[0], opt->url, opt->timeout*1000, opt->code, result);
    close(fd[0]);
    if (child > 0) {
        int status = 0;
        pid_t done;
        do { done = waitpid(child, &status, WNOHANG); } while (done < 0 && errno == EINTR);
        if (done == 0) {
            kill(child, SIGKILL);
            while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        } else if (done == child && WIFEXITED(status) && WEXITSTATUS(status) == 2 && !ok)
            result->detail = "unsupported_xhttp_transport";
    }
    return ok;
}

void probe_node(struct probe_job job, json_object *config, const struct https_options *opt,
                uint32_t mark)
{
    struct node_profile p;
    struct measurement m = {.state = "unsupported", .checked = time(NULL)};
    const char *reason = config ? node_profile_parse(config, job.out, job.member, &p) : "config_unavailable";
    if (reason) {
        m.detail = reason;
        job.member->https = m;
        return;
    }
    uint32_t socket_mark = p.has_mark ? p.mark : mark;
    struct node_https_result r = {.detail = "probe_unavailable"};
    int ok;
    if (p.kind == NODE_VLESS_XHTTP) {
        if (p.http_version == 2 && !(curl_version_info(CURLVERSION_NOW)->features & CURL_VERSION_HTTP2)) {
            m.detail = "HTTP/2 unavailable in libcurl";
            job.member->https = m;
            return;
        }
        job.member->standard_tls = *p.fingerprint != 0;
        ok = via_xhttp(&p, opt, socket_mark, &r);
    } else {
        const char *scheme = p.kind == NODE_SOCKS5 ? "socks5h" : p.kind == NODE_HTTP ? "http" : "https";
        struct node_https_proxy proxy = {scheme, p.host, p.username, p.password, p.port};
        ok = node_https_proxy(&proxy, opt->url, opt->timeout*1000, socket_mark, opt->code, &r);
    }
    m.checked = time(NULL);
    m.state = ok ? "ok" : "error";
    m.detail = r.detail;
    if (!ok && r.detail && !strncmp(r.detail, "unsupported", 11)) m.state = "unsupported";
    m.ms = r.ms;
    job.member->http_code = r.http_code;
    job.member->https = m;
}
