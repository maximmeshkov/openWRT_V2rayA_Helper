#ifndef V2RAYA_HELPER_CORE_KIND_H
#define V2RAYA_HELPER_CORE_KIND_H

/* How to drive each core v2rayA can run. */
struct core_kind {
	const char *variant;           /* "variant" in GET /api/version */
	const char *asset_env;         /* variable naming the geo files directory */
	const char *const *test_args;  /* config check that reads the config from stdin */
	const char *const *run_args;   /* run that reads the config from stdin */
};

/* NULL for a variant v2rayA reports as Unknown or one this table lacks. */
const struct core_kind *core_kind_of(const char *variant);

#endif
