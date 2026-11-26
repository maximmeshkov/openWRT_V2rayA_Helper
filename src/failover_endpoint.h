#ifndef V2RAYA_HELPER_FAILOVER_ENDPOINT_H
#define V2RAYA_HELPER_FAILOVER_ENDPOINT_H

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#define FAILOVER_ENDPOINT_LIMIT 263

/* Match host and port across catalogue positions, profiles and subscriptions.
 * This is address normalization, with no DNS lookup. */
static inline int failover_endpoint_normalize(const char *address, char out[FAILOVER_ENDPOINT_LIMIT + 1])
{
    out[0] = '\0';
    const char *separator = address ? strrchr(address, ':') : NULL;
    if (!separator || separator == address) return 0;

    unsigned port = 0;
    for (const char *p = separator + 1; *p; ++p) {
        if (*p < '0' || *p > '9') return 0;
        port = port * 10 + (unsigned)(*p - '0');
        if (port > 65535) return 0;
    }
    if (!port) return 0;

    int bracketed = *address == '[';
    size_t length = (size_t)(separator - address);
    if (bracketed) {
        if (length < 3 || separator[-1] != ']') return 0;
        ++address;
        length -= 2;
    } else if (strchr(address, ':') != separator) {
        return 0;
    }

    char host[255], literal[INET6_ADDRSTRLEN];
    if (!length || length >= sizeof(host)) return 0;
    memcpy(host, address, length);
    host[length] = '\0';

    struct in_addr ipv4;
    struct in6_addr ipv6;
    const char *normalized = literal;
    if (bracketed) {
        if (inet_pton(AF_INET6, host, &ipv6) != 1) return 0;
        if (IN6_IS_ADDR_V4MAPPED(&ipv6)) {
            memcpy(&ipv4, &ipv6.s6_addr[12], sizeof(ipv4));
            if (!inet_ntop(AF_INET, &ipv4, literal, sizeof(literal))) return 0;
            bracketed = 0;
        } else if (!inet_ntop(AF_INET6, &ipv6, literal, sizeof(literal))) {
            return 0;
        }
    } else {
        if (host[length - 1] == '.') host[--length] = '\0';
        if (!length || length > 253) return 0;
        if (inet_pton(AF_INET, host, &ipv4) == 1) {
            if (!inet_ntop(AF_INET, &ipv4, literal, sizeof(literal))) return 0;
        } else {
            /* Avoid legacy numeric IP spellings, including hexadecimal aliases. */
            if (inet_aton(host, &ipv4)) return 0;
            size_t label = 0;
            int nonnumeric = 0;
            for (char *p = host; *p; ++p) {
                if (*p == '.') {
                    if (!label) return 0;
                    label = 0;
                    continue;
                }
                if (++label > 63) return 0;
                if (*p >= 'A' && *p <= 'Z') *p += 'a' - 'A';
                if (*p >= '0' && *p <= '9') continue;
                if ((*p < 'a' || *p > 'z') && *p != '_' && *p != '-') return 0;
                nonnumeric = 1;
            }
            if (!label || !nonnumeric) return 0;
            normalized = host;
        }
    }

    snprintf(out, FAILOVER_ENDPOINT_LIMIT + 1, bracketed ? "[%s]:%u" : "%s:%u", normalized, port);
    return 1;
}

#endif
