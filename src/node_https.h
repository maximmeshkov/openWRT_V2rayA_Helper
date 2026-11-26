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

/* Both functions return 1 only for a verified TLS response with expected_code.
 * A proxy scheme is socks5h, socks4a, http or https. Its address has no port.
 * The fd variant takes a connected byte stream to the HTTPS origin and leaves
 * fd open. It never resolves or opens a network connection to the origin. */
int node_https_proxy(const struct node_https_proxy *proxy, const char *url,
                     long timeout_ms, uint32_t mark, long expected_code,
                     struct node_https_result *result);
int node_https_fd(int fd, const char *url, long timeout_ms, long expected_code,
                  struct node_https_result *result);

#endif
