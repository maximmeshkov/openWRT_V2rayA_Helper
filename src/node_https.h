#ifndef V2RAYA_HELPER_NODE_HTTPS_H
#define V2RAYA_HELPER_NODE_HTTPS_H

#include <stdint.h>

struct node_https_proxy {
    const char *scheme, *address, *username, *password;
    int port;
};

struct node_https_result {
    const char *detail;
    long ms, http_code;
};

/* Returns 1 only for a verified TLS response with expected_code; a body over
 * 64 KiB is cut off after the status line. A proxy scheme is socks5h,
 * socks4a, http or https. Its address has no port. */
int node_https_proxy(const struct node_https_proxy *proxy, const char *url,
                     long timeout_ms, uint32_t mark, long expected_code,
                     struct node_https_result *result);

#endif
