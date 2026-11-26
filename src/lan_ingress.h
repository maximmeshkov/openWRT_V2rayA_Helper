#ifndef V2RAYA_HELPER_LAN_INGRESS_H
#define V2RAYA_HELPER_LAN_INGRESS_H

#include "core_watch.h"
#include "v2raya_api.h"
#include <stdint.h>
#include <signal.h>
#include <sys/stat.h>

struct lan_ingress {
    const char *mode;
    const char *backend;
    const char *ipv4;
    const char *ipv6;
    const char *reason;
    const char *ipv4_reason;
    const char *ipv6_reason;
};

struct lan_ingress_watch {
    struct core_watch_sample core;
    struct stat config;
    int families;
    int64_t missing_since;
};

struct lan_redirect_repair {
    json_object *witness;
    struct redirect_checkpoint *checkpoint;
    int checkpoint_error;
    int64_t missing_since, retry_at;
};

struct lan_ingress lan_ingress_parse_nft(const char *output, json_object **identity);
enum lan_nft_table_state { LAN_NFT_UNKNOWN, LAN_NFT_PRESENT, LAN_NFT_ABSENT };
enum lan_nft_table_state lan_ingress_nft_tables(const char *output);
struct lan_ingress lan_ingress_observe(const struct v2raya_api *api, const char *config_path, json_object *config,
                                      struct lan_ingress_watch *watch, struct lan_redirect_repair *repair,
                                      const volatile sig_atomic_t *stopping);
void lan_ingress_disarm(struct lan_redirect_repair *repair);
void lan_ingress_init(struct lan_redirect_repair *repair, const char *path, const char *api, const char *config);
void lan_ingress_close(struct lan_redirect_repair *repair);

#endif
