#ifndef V2RAYA_HELPER_CAPABILITY_H
#define V2RAYA_HELPER_CAPABILITY_H

#include <stddef.h>
#include <json-c/json.h>

/* Changes the helper may ask v2rayA to make. Monitoring and probes only read,
 * so they work on any v2rayA whose answers parse and need no permission. */
enum feature {
	FEATURE_SWITCH,           /* connect a reserve server by policy */
	FEATURE_ROUTING_SAVE,     /* write RoutingA */
	FEATURE_CORE_START,       /* start a core that crashed */
	FEATURE_REDIRECT_RESTORE, /* put back the stock LAN REDIRECT rule */
};

enum capability {
	CAPABILITY_DENIED = 0,
	CAPABILITY_VERIFIED,  /* this v2rayA build is in the verified table */
	CAPABILITY_OPTED_IN,  /* the administrator allowed this exact version */
};

/* The UCI option allow_unverified reaches every helper process through this
 * variable. Its value is one exact v2rayA version, so an upgrade of v2rayA
 * turns the opt-in off again. */
#define CAPABILITY_OPT_IN_ENV "V2RAYA_HELPER_ALLOW_UNVERIFIED"

/* Decide one feature from GET /api/version data. On denial, writes the
 * user-facing reason. */
enum capability capability_decide(json_object *version_data, enum feature feature, char *reason, size_t len);

struct v2raya_api;
/* Read /api/version and decide one feature. */
enum capability capability_check_api(const struct v2raya_api *api, enum feature feature, char *reason, size_t len);

#endif
