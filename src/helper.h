#ifndef V2RAYA_HELPER_H
#define V2RAYA_HELPER_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
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
    int standard_tls;
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

int load_inventory(const char *api, const char *token_file, const char *xray_config, long timeout_ms,
                   struct inventory *out, char *error, size_t error_len);
void free_inventory(struct inventory *inv);
json_object *fetch_json(const char *url, const char *token, long timeout_ms,
                        char *error, size_t error_len);
struct probe_job {
    struct outbound *out;
    struct member *member;
};
struct https_options {
    const char *url;
    char host[256];
    int port;
    long code, interval, timeout;
};
void probe_members(struct probe_job *jobs, size_t count, long timeout_ms, uint32_t mark,
                   const struct https_options *https, json_object *config);
void probe_node(struct probe_job job, json_object *config, const struct https_options *options,
                uint32_t mark);
CURLU *endpoint_url(const char *address);
int64_t probe_clock_ms(void);
struct measurement probe_quic(const char *address, long timeout_ms, uint32_t mark);
void read_observatory(const char *url, struct inventory *inv, long timeout_ms, long max_age);
int valid_observatory_url(const char *url);
int https_target(const char *url, char *host, size_t size, int *port);
json_object *read_rpc_json(void);
const char *rpc_string(json_object *request, const char *key);

#endif
