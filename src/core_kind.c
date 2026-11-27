#include "core_kind.h"
#include <string.h>

/* Xray: main/run.go ("run -test", "stdin:"). v2rayA 2.4+ runs its own Xray
 * fork, v2raya_core, with the same flags (core/main/run.go@v2.5.16) and the
 * same asset variable. */
static const char *const xray_test[] = {"run", "-test", "-c", "stdin:", NULL};
static const char *const xray_run[] = {"run", "-c", "stdin:", NULL};
/* V2Ray v5: main/commands/{test,run}.go. It has no "stdin:" name, so it reads
 * /dev/stdin; not yet run against a real v5 binary. */
static const char *const v2ray_test[] = {"test", "-format=json", "-c", "/dev/stdin", NULL};
static const char *const v2ray_run[] = {"run", "-format=json", "-c", "/dev/stdin", NULL};

static const struct core_kind kinds[] = {
	{"Xray", "XRAY_LOCATION_ASSET", xray_test, xray_run},
	{"V2rayaCore", "XRAY_LOCATION_ASSET", xray_test, xray_run},
	{"V2Ray", "V2RAY_LOCATION_ASSET", v2ray_test, v2ray_run},
};

const struct core_kind *core_kind_of(const char *variant)
{
	for (size_t i = 0; variant && i < sizeof(kinds) / sizeof(kinds[0]); i++)
		if (!strcmp(kinds[i].variant, variant)) return &kinds[i];
	return NULL;
}
