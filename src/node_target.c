#include "helper.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Both curl and the VLESS request must use the same target. IPv6 literals
 * keep their URL brackets; zone IDs, credentials and fragments are rejected. */
int https_target(const char *raw, char *host_out, size_t capacity, int *port_out)
{
    if (!raw || !host_out || !port_out || strncasecmp(raw, "https://", 8)) return 0;
    for (const unsigned char *p = (const unsigned char *)raw; *p; p++)
        if (*p <= ' ' || *p == 127 || *p == '\\' || *p == '#') return 0;
    CURLU *u = curl_url();
    char *host = NULL, *port = NULL, *zone = NULL;
    int ok = 0;
    if (!u || curl_url_set(u, CURLUPART_URL, raw, CURLU_DISALLOW_USER) ||
        curl_url_get(u, CURLUPART_HOST, &host, 0) ||
        curl_url_get(u, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT) ||
        curl_url_get(u, CURLUPART_ZONEID, &zone, 0) == CURLUE_OK ||
        !*host || !*port || strlen(port) > 5) goto done;
    int number = atoi(port);
    if (number < 1 || number > 65535) goto done;
    if (*host == '[') {
        struct in6_addr ip;
        char literal[INET6_ADDRSTRLEN];
        size_t n = strlen(host);
        if (n < 3 || host[n-1] != ']' || n-2 >= sizeof(literal)) goto done;
        memcpy(literal, host+1, n-2);
        literal[n-2] = '\0';
        if (inet_pton(AF_INET6, literal, &ip) != 1 || !inet_ntop(AF_INET6, &ip, literal, sizeof(literal)) ||
            strlen(literal) + 3 > capacity) goto done;
        snprintf(host_out, capacity, "[%s]", literal);
    } else {
        size_t n = strlen(host);
        if (n > 255 || n >= capacity ||
            strspn(host, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") != n) goto done;
        memcpy(host_out, host, n+1);
    }
    *port_out = number;
    ok = 1;
done:
    curl_free(host);
    curl_free(port);
    curl_free(zone);
    if (u) curl_url_cleanup(u);
    return ok;
}
