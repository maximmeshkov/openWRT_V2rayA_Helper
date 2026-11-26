#ifndef V2RAYA_HELPER_CORE_RECOVERY_H
#define V2RAYA_HELPER_CORE_RECOVERY_H

#include <signal.h>
#include <stdint.h>
#include "core_watch.h"
#include "v2raya_api.h"

enum { CORE_RECOVERY_MAX_ATTEMPTS = 3 };

struct core_recovery {
    struct core_watch_sample witness;
    int64_t missing_since, last_attempt;
    unsigned attempts;
    int checkpoint_required, checkpoint_dirty;
    struct recovery_checkpoint *checkpoint;
};

void core_recovery_init(struct core_recovery *state, const char *path, const char *api,
                        const char *config_path);
void core_recovery_close(struct core_recovery *state);

/* A non-NULL message replaces successful independent probe readings while Xray is missing. */
const char *core_recovery_tick(struct core_recovery *state, const struct v2raya_api *api,
                              const char *config_path, int intended_running,
                              const volatile sig_atomic_t *stopping);

#endif
