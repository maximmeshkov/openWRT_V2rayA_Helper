#ifndef V2RAYA_HELPER_RECOVERY_CHECKPOINT_H
#define V2RAYA_HELPER_RECOVERY_CHECKPOINT_H

#include "core_recovery.h"

struct recovery_checkpoint *recovery_checkpoint_open(const char *path, const char *api,
                                                     const char *config_path, struct core_recovery *state);
int recovery_checkpoint_save(struct recovery_checkpoint *checkpoint, const struct core_recovery *state);
void recovery_checkpoint_close(struct recovery_checkpoint *checkpoint);

#endif
