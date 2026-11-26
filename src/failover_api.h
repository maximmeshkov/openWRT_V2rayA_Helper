#ifndef V2RAYA_HELPER_FAILOVER_API_H
#define V2RAYA_HELPER_FAILOVER_API_H

#include "v2raya_api.h"
#include <stdint.h>

struct failover_node {
    int64_t id, sub;
    const char *name, *address, *net;
    /* Private subscription identity. Never put it in UI or policy data. */
    const char *subscription_key;
    char key[33];
};

struct failover_subscription {
    char key[33];
    const char *name;
    size_t first, count;
};

struct catalogue_key;

struct failover_catalogue {
    json_object *data;
    struct failover_node *nodes;
    size_t count;
    struct failover_subscription *subscriptions;
    size_t subscription_count;
    struct catalogue_key *node_keys, *subscription_keys;
    int running;
};

int failover_catalogue_read(const struct v2raya_api *api, struct failover_catalogue *catalogue,
                            char *error, size_t len);
void failover_catalogue_free(struct failover_catalogue *catalogue);
const struct failover_node *failover_catalogue_find(const struct failover_catalogue *catalogue, const char *key);
const struct failover_subscription *failover_catalogue_subscription(const struct failover_catalogue *catalogue,
                                                                   const char *key);
const struct failover_node *failover_catalogue_active(const struct failover_catalogue *catalogue, const char *outbound);

/* The returned link is private and caller-owned. It can contain credentials. */
char *failover_api_profile(const struct v2raya_api *api, const struct failover_node *node, char *error, size_t len);
int failover_api_can_switch(const struct v2raya_api *api, char *error, size_t len);

/* The upstream check and POST are separate. Rechecks narrow the race with
 * edits in v2rayA, whose API has no conditional connect operation. */
int failover_api_connect(const struct v2raya_api *api, const char *outbound,
                         const struct failover_node *expected_active, const struct failover_node *candidate,
                         const char *expected_profile, const char *expected_subscription,
                         int (*permitted)(void *), void *context,
                         char *error, size_t len);

#endif
