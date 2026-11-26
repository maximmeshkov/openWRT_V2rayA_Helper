#ifndef V2RAYA_HELPER_PRIVATE_STATE_H
#define V2RAYA_HELPER_PRIVATE_STATE_H

#include <stddef.h>

struct private_state;

/* Open and lock one runtime file in a same-owner private directory. */
struct private_state *private_state_open(const char *path);
/* Return 1 for a complete record, 0 for absence, or -1 for an invalid read. */
int private_state_read(struct private_state *state, void *buffer, size_t capacity, size_t *length);
/* Replace the record only if it still matches the last successful read or write. */
int private_state_write(struct private_state *state, const void *data, size_t length);
void private_state_close(struct private_state *state);

#endif
