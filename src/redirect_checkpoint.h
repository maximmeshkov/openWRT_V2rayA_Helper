#ifndef V2RAYA_HELPER_REDIRECT_CHECKPOINT_H
#define V2RAYA_HELPER_REDIRECT_CHECKPOINT_H

#include <json-c/json.h>
#include <stdint.h>

struct redirect_checkpoint;
struct redirect_checkpoint *redirect_checkpoint_open(const char *path, const char *api, const char *config_path,
                                                     json_object **witness, int64_t *retry_at);
int redirect_checkpoint_save(struct redirect_checkpoint *checkpoint, json_object *witness, int64_t retry_at);
void redirect_checkpoint_close(struct redirect_checkpoint *checkpoint);

#endif
