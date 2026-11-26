#ifndef V2RAYA_HELPER_XHTTP_TRANSPORT_H
#define V2RAYA_HELPER_XHTTP_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>

/* A single VLESS byte stream. The caller checks the complete Xray profile
 * before using this TLS transport. All strings live for the call's duration. */
struct node_profile;

enum xhttp_status {
    XHTTP_EOF = 0,
    XHTTP_SESSION_FAILED = 1, /* No complete VLESS response header. */
    XHTTP_UNSUPPORTED = 2,
    XHTTP_STREAM_FAILED = 3   /* Transport failed after VLESS answered. */
};

/* Blocks in a bounded worker while relaying an already-connected private
 * socketpair. Prepends the VLESS request and consumes the response header.
 * Caller retains ownership of stream_fd. Returns an xhttp_status. */
int xhttp_relay(const struct node_profile *ep, const unsigned char *prefix,
                size_t prefix_len, int stream_fd, uint32_t mark, long timeout_ms);

#endif
