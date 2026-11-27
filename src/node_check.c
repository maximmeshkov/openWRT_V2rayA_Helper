#define _GNU_SOURCE
#include "helper.h"
#include "node_profile.h"
#include "node_https.h"
#include "probe_core.h"
#include <string.h>

/* A slow router may take a few seconds to start the core even with this small config. */
enum { PROBE_CORE_STARTUP_MS = 5000, PROBE_CORE_MAX = 16 };

pid_t probe_core_launch(json_object *const *outbounds, size_t count, const struct https_options *https,
                        uint32_t mark, int *ports)
{
    if (!count || count > PROBE_CORE_MAX || !https->core || !https->core_binary || probe_core_ports(ports, count))
        return -1;
    json_object *probe = probe_core_config(outbounds, ports, count, mark);
    pid_t core = probe ? probe_core_start(https->core, https->core_binary, probe, ports, count,
                                          PROBE_CORE_STARTUP_MS) : -1;
    json_object_put(probe);
    return core;
}

pid_t probe_core_for_jobs(struct probe_job *jobs, size_t count, json_object *config,
                          const struct https_options *https, uint32_t mark, int *ports)
{
    json_object *outbounds[PROBE_CORE_MAX] = {0};
    size_t owner[PROBE_CORE_MAX], used = 0;
    for (size_t i = 0; config && i < count && i < PROBE_CORE_MAX; i++) {
        struct node_profile p;
        if (!node_profile_parse(config, jobs[i].out, jobs[i].member, &p) && p.kind == NODE_CORE) {
            owner[used] = i;
            outbounds[used++] = p.outbound;
        }
    }
    int chosen[PROBE_CORE_MAX];
    pid_t core = probe_core_launch(outbounds, used, https, mark, chosen);
    for (size_t k = 0; core > 0 && k < used; k++) ports[owner[k]] = chosen[k];
    return core;
}

struct measurement probe_https_profile(struct node_profile *p, const struct https_options *opt,
                                       uint32_t mark, int core_port, long *http_code)
{
    struct measurement m = {.state = "unknown", .detail = "probe_core_unavailable", .checked = time(NULL)};
    *http_code = 0;
    struct node_https_proxy proxy;
    uint32_t socket_mark;
    if (p->kind == NODE_CORE) {
        if (!core_port) return m;
        /* The probe core marks its own connection to the server; this hop stays on loopback. */
        proxy = (struct node_https_proxy){"socks5h", "127.0.0.1", NULL, NULL, core_port};
        socket_mark = 0;
    } else {
        const char *scheme = p->kind == NODE_SOCKS5 ? "socks5h" : p->kind == NODE_HTTP ? "http" : "https";
        proxy = (struct node_https_proxy){scheme, p->host, p->username, p->password, p->port};
        socket_mark = p->has_mark ? p->mark : mark;
    }
    struct node_https_result r = {.detail = "probe_unavailable"};
    int ok = node_https_proxy(&proxy, opt->url, opt->timeout*1000, socket_mark, opt->code, &r);
    m.checked = time(NULL);
    m.state = ok ? "ok" : "error";
    m.detail = r.detail;
    if (!ok && r.detail && !strncmp(r.detail, "unsupported", 11)) m.state = "unsupported";
    m.ms = r.ms;
    *http_code = r.http_code;
    return m;
}

void probe_node(struct probe_job job, json_object *config, const struct https_options *opt,
                uint32_t mark, int core_port)
{
    struct node_profile p;
    const char *reason = config ? node_profile_parse(config, job.out, job.member, &p) : "config_unavailable";
    if (reason) {
        job.member->https = (struct measurement){.state = "unsupported", .detail = reason, .checked = time(NULL)};
        return;
    }
    job.member->https = probe_https_profile(&p, opt, mark, core_port, &job.member->http_code);
}
