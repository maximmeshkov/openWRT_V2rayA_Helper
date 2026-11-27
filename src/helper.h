#ifndef V2RAYA_HELPER_H
#define V2RAYA_HELPER_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <curl/curl.h>
#include <json-c/json.h>

struct measurement {
    const char *state, *detail;
    long ms;
    time_t checked;
};

struct member {
    char *name, *address;
    const char *transport;
    char *display_net;
    char key[33];
    int64_t node_id, subscription;
    int selected;
    struct measurement server;
    struct measurement https;
    long http_code;
};

struct outbound {
    char *name;
    struct member *members;
    size_t count;
    time_t since;
    struct measurement route;
};

struct inventory {
    int running;
    struct outbound *outbounds;
    size_t count;
};

enum { INVENTORY_AUTH_REQUIRED = -2 };

struct v2raya_api;
int load_inventory(const struct v2raya_api *api, const char *xray_config,
                   struct inventory *out, char *error, size_t error_len);
void free_inventory(struct inventory *inv);
json_object *fetch_json(const char *url, const char *token, long timeout_ms,
                        char *error, size_t error_len);
struct probe_job {
    const struct outbound *out;
    struct member *member;
};
struct core_kind;
struct https_options {
    const char *url;
    char host[256];
    int port;
    long code, interval, timeout;
    /* The core v2rayA runs; the probe core starts the same binary. NULL when unknown. */
    const char *core_binary;
    const struct core_kind *core;
};
void probe_members(struct probe_job *jobs, size_t count, long timeout_ms, uint32_t mark,
                   const struct https_options *https, json_object *config);
/* core_port: the probe core's SOCKS port for this member, or 0. */
void probe_node(struct probe_job job, json_object *config, const struct https_options *options,
                uint32_t mark, int core_port);
/* Start a probe core for these outbounds; ports[i] gets outbound i's SOCKS port.
 * Returns the core's PID, or -1 when the core is unknown or did not start. */
pid_t probe_core_launch(json_object *const *outbounds, size_t count, const struct https_options *https,
                        uint32_t mark, int *ports);
/* Start one probe core for the jobs whose server only the core can reach.
 * ports[i] gets that job's SOCKS port or stays 0. Returns the core's PID or -1. */
pid_t probe_core_for_jobs(struct probe_job *jobs, size_t count, json_object *config,
                          const struct https_options *https, uint32_t mark, int *ports);
CURLU *endpoint_url(const char *address);
int64_t probe_clock_ms(void);
struct measurement probe_quic(const char *address, long timeout_ms, uint32_t mark);
void read_observatory(const char *url, struct inventory *inv, long timeout_ms, long max_age);
int valid_observatory_url(const char *url);
int https_target(const char *url, char *host, size_t size, int *port);
json_object *read_rpc_json(void);
const char *rpc_string(json_object *request, const char *key);

#endif
