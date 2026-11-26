#ifndef V2RAYA_HELPER_LAN_INGRESS_NETLINK_H
#define V2RAYA_HELPER_LAN_INGRESS_NETLINK_H

#include <stdint.h>

int lan_ingress_generation(uint32_t *generation);
/* A matching snapshot is required. Families is 1 for IPv4 or 2 for IPv4 and IPv6. */
int lan_ingress_restore(uint32_t generation, int families);

#endif
