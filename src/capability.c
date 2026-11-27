#include "capability.h"
#include "v2raya_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FEATURE_BIT(feature) (1u << (feature))

/* v2rayA versions whose write paths behave like the tested one. 2.2.7.4 ran in
 * tests/xray_recovery_lab.py. The other 2.2.x builds include those shipped by
 * OpenWrt 23.05 (2.2.6.7), 24.10 (2.2.7.3) and 25.12 (2.2.7.5); between each
 * of them and 2.2.7.4, git diff shows no change in service/core/v2ray
 * (connections, process manager), service/server/controller,
 * service/db/configure or the REDIRECT rules, apart from the TPROXY white IP
 * groups added in 2.2.7.4. */
static const char *const verified_versions[] = {
	"2.2.6.7", "2.2.7", "2.2.7.1", "2.2.7.2", "2.2.7.3", "2.2.7.4", "2.2.7.5",
};

/* These also depend on the core v2rayA runs, and were tested only with Xray.
 * RoutingA lives in v2rayA's database whatever the core. */
static const unsigned tested_with_xray_only =
	FEATURE_BIT(FEATURE_SWITCH) | FEATURE_BIT(FEATURE_CORE_START) | FEATURE_BIT(FEATURE_REDIRECT_RESTORE);

static const char *text(json_object *object, const char *key)
{
	json_object *value = json_object_object_get(object, key);
	return json_object_is_type(value, json_type_string) ? json_object_get_string(value) : NULL;
}

static int verified(const char *version, const char *variant, enum feature feature)
{
	for (size_t i = 0; i < sizeof(verified_versions) / sizeof(verified_versions[0]); i++)
		if (!strcmp(verified_versions[i], version))
			return !(tested_with_xray_only & FEATURE_BIT(feature)) || !strcmp(variant, "Xray");
	return 0;
}

/* An opt-in cannot cover what depends on one version's internals. Restoring
 * the firewall copies the 2.2.x REDIRECT template. Switching expects a new
 * connection to replace the outbound's server, which v2rayA does only for
 * Xray up to 2.2.x (service/core/v2ray/connect.go@v2.2.7.4); later versions
 * and the V2Ray core add the server to the outbound instead. */
static int opt_in_covers(const char *version, const char *variant, enum feature feature)
{
	const char *opted = getenv(CAPABILITY_OPT_IN_ENV);
	if (!opted || strcmp(opted, version)) return 0;
	switch (feature) {
	case FEATURE_ROUTING_SAVE:
	case FEATURE_CORE_START:
		return 1;
	case FEATURE_SWITCH:
		return !strcmp(variant, "Xray") && !strncmp(version, "2.2.", 4);
	default:
		return 0;
	}
}

static const char *const feature_names[] = {
	[FEATURE_SWITCH] = "automatic server switching",
	[FEATURE_ROUTING_SAVE] = "saving RoutingA",
	[FEATURE_CORE_START] = "starting a crashed core",
	[FEATURE_REDIRECT_RESTORE] = "restoring the LAN REDIRECT rule",
};

enum capability capability_decide(json_object *version_data, enum feature feature, char *reason, size_t len)
{
	const char *version = text(version_data, "version"), *variant = text(version_data, "variant");
	if (!version || !*version) {
		snprintf(reason, len, "v2rayA did not report its version");
		return CAPABILITY_DENIED;
	}
	if (!variant) variant = ""; /* only the core-dependent changes need it */
	if (verified(version, variant, feature)) return CAPABILITY_VERIFIED;
	if (opt_in_covers(version, variant, feature)) return CAPABILITY_OPTED_IN;
	snprintf(reason, len, "%s is not verified for v2rayA %s with the %s core",
	         feature_names[feature], version, *variant ? variant : "unknown");
	return CAPABILITY_DENIED;
}

enum capability capability_check_api(const struct v2raya_api *api, enum feature feature, char *reason, size_t len)
{
	json_object *version_data = v2raya_api_version_data(api, reason, len);
	if (!version_data) return CAPABILITY_DENIED;
	enum capability result = capability_decide(version_data, feature, reason, len);
	json_object_put(version_data);
	return result;
}
