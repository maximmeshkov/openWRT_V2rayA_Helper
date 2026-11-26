#ifndef V2RAYA_HELPER_XHTTP_TRANSPORT_H
#define V2RAYA_HELPER_XHTTP_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>

/* A single VLESS byte stream. The caller checks the complete Xray profile
 * before using this TLS transport. All strings live for the call's duration. */
struct node_profile;

/* Blocks in a bounded worker while relaying an already-connected private
 * socketpair. Prepends the VLESS request and consumes the response header.
 * Caller retains ownership of stream_fd. Returns 0 on EOF,
 * 1 on transport failure, 2 for an unsupported profile or libcurl build. */
int xhttp_relay(const struct node_profile *ep, const unsigned char *prefix,
                size_t prefix_len, int stream_fd, uint32_t mark, long timeout_ms);

#endif
