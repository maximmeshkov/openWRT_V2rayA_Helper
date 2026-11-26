#ifndef V2RAYA_HELPER_LAN_TPROXY_NFT_H
#define V2RAYA_HELPER_LAN_TPROXY_NFT_H

#include "lan_ingress.h"

/* Recognize the native v2rayA 2.2.7.4 table and describe its PREROUTING hook. */
struct lan_ingress lan_tproxy_parse_nft(const char *output);

#endif
