#define _GNU_SOURCE
#include "recovery_checkpoint.h"
#include "helper.h"
#include "boot_id.h"
#include "private_state.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const char format[8] = "VRACORE1";

/* Local, same-boot state. Its format is private to this implementation. */
struct recovery_record {
    char format[8], boot[37], api[64], config[PATH_MAX];
    uint64_t pid_namespace, net_namespace, owner_started;
    int64_t last_attempt;
    int32_t owner, core, port;
    uint32_t attempts;
};

struct recovery_checkpoint {
    struct recovery_record identity;
    struct private_state *file;
};

static int current_identity(struct recovery_record *record, const char *api, const char *config)
{
    if (strlen(api) >= sizeof(record->api) || strlen(config) >= sizeof(record->config)) return 0;
    struct stat ns;
    /* Some OpenWrt targets are built without these Linux namespace types. */
    if (!stat("/proc/self/ns/pid", &ns)) record->pid_namespace = ns.st_ino;
    else if (errno != ENOENT) return 0;
    if (!stat("/proc/self/ns/net", &ns)) record->net_namespace = ns.st_ino;
    else if (errno != ENOENT) return 0;
    if (!boot_id_read(record->boot)) return 0;
    /* Preserve the checkpoint format used by releases before boot_id_read(). */
    record->boot[BOOT_ID_LENGTH] = '\n';
    memcpy(record->format, format, sizeof(format));
    strcpy(record->api, api);
    strcpy(record->config, config);
    return 1;
}

/* Return zero for a missing file and reject any existing file with another use. */
static int read_record(const struct recovery_checkpoint *checkpoint, struct recovery_record *record)
{
    size_t length;
    int exists = private_state_read(checkpoint->file, record, sizeof(*record), &length);
    if (exists != 1) return exists;
    return length == sizeof(*record) && !memcmp(record->format, format, sizeof(format)) ? 1 : -1;
}

static int read_checkpoint(struct recovery_checkpoint *checkpoint, struct core_recovery *state)
{
    struct recovery_record saved;
    int exists = read_record(checkpoint, &saved);
    if (exists <= 0) return exists == 0;
    const struct recovery_record *id = &checkpoint->identity;
    if (memcmp(saved.boot, id->boot, sizeof(saved.boot)) || memcmp(saved.api, id->api, sizeof(saved.api)) ||
        memcmp(saved.config, id->config, sizeof(saved.config)) || saved.pid_namespace != id->pid_namespace ||
        saved.net_namespace != id->net_namespace)
        return 1;
    if (saved.last_attempt < 0 || saved.last_attempt > probe_clock_ms() ||
        saved.attempts > CORE_RECOVERY_MAX_ATTEMPTS ||
        saved.owner < 0 || saved.core < 0 || saved.port < 0 || saved.port > 65535 ||
        (saved.owner && (!saved.owner_started || !saved.port)) ||
        (!saved.owner && (saved.core || saved.owner_started || saved.port)) ||
        (saved.attempts && (!saved.owner || !saved.last_attempt)))
        return 0;

    state->witness = (struct core_watch_sample){.owner = saved.owner, .core = saved.core,
                                               .owner_started = saved.owner_started, .port = saved.port};
    state->last_attempt = saved.last_attempt;
    state->attempts = saved.attempts;
    return 1;
}

struct recovery_checkpoint *recovery_checkpoint_open(const char *path, const char *api,
                                                     const char *config, struct core_recovery *state)
{
    struct recovery_checkpoint *checkpoint = calloc(1, sizeof(*checkpoint));
    if (!checkpoint) return NULL;
    checkpoint->file = private_state_open(path);
    if (checkpoint->file && current_identity(&checkpoint->identity, api, config) &&
        read_checkpoint(checkpoint, state))
        return checkpoint;
    recovery_checkpoint_close(checkpoint);
    return NULL;
}

int recovery_checkpoint_save(struct recovery_checkpoint *checkpoint, const struct core_recovery *state)
{
    if (!checkpoint) return !state->checkpoint_required;
    struct recovery_record record;
    memcpy(&record, &checkpoint->identity, sizeof(record));
    record.owner = state->witness.owner;
    record.owner_started = state->witness.owner_started;
    record.core = state->witness.core;
    record.port = state->witness.port;
    record.last_attempt = state->last_attempt;
    record.attempts = state->attempts;
    return private_state_write(checkpoint->file, &record, sizeof(record));
}

void recovery_checkpoint_close(struct recovery_checkpoint *checkpoint)
{
    if (!checkpoint) return;
    private_state_close(checkpoint->file);
    free(checkpoint);
}
