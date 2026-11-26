#ifndef V2RAYA_HELPER_FAILOVER_PROFILE_H
#define V2RAYA_HELPER_FAILOVER_PROFILE_H

#include "node_profile.h"

struct failover_profile {
    struct node_profile node;
    json_object *storage;
};

/* Parse a trusted v2rayA catalogue export into an initially empty profile.
 * Credential strings stay alive until clear and must never be published.
 * NULL means success; errors are static strings with no URI content. */
const char *failover_profile_parse(const char *uri, struct failover_profile *profile);
void failover_profile_clear(struct failover_profile *profile);

#endif
