#define _GNU_SOURCE
#include "failover_cooldown.h"
#include "boot_id.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const uint64_t ns_per_second = UINT64_C(1000000000);

struct cooldown_record {
    char boot_id[BOOT_ID_LENGTH + 1];
    uint64_t wall, uptime_ns, duration;
};

static int field(const char **cursor, char delimiter, uint64_t *value)
{
    if (**cursor < '0' || **cursor > '9') return 0;
    errno = 0;
    char *end;
    unsigned long long parsed = strtoull(*cursor, &end, 10);
    if (errno || *end != delimiter) return 0;
    *cursor = end + 1;
    *value = parsed;
    return 1;
}

/* Return zero when no pause has ever been recorded. */
static int read_record(const char *path, struct cooldown_record *record)
{
    *record = (struct cooldown_record){0};
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    struct stat info;
    char buffer[160];
    ssize_t used = fstat(fd, &info) || !S_ISREG(info.st_mode) ? -1 : read(fd, buffer, sizeof(buffer));
    close(fd);
    if (used <= 0 || used >= (ssize_t)sizeof(buffer) || memchr(buffer, '\0', (size_t)used)) return -1;
    buffer[used] = '\0';

    const char *p = buffer;
    if (!strncmp(p, "v2 ", 3)) {
        p += 3;
        if (strlen(p) <= BOOT_ID_LENGTH || p[BOOT_ID_LENGTH] != ' ') return -1;
        memcpy(record->boot_id, p, BOOT_ID_LENGTH);
        p += BOOT_ID_LENGTH + 1;
        if (!boot_id_valid(record->boot_id) || !field(&p, ' ', &record->wall) ||
            !field(&p, ' ', &record->duration) || !field(&p, '\n', &record->uptime_ns)) return -1;
    } else {
        uint64_t until;
        if (!field(&p, ' ', &record->wall) || !field(&p, '\n', &until) || !record->wall ||
            until < record->wall) return -1;
        record->duration = until - record->wall;
    }
    return !*p && record->duration <= FAILOVER_MAX_COOLDOWN ? 1 : -1;
}

static int uptime_ns(uint64_t *now)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_BOOTTIME, &ts) || ts.tv_sec < 0 ||
        (uint64_t)ts.tv_sec > (UINT64_MAX - (uint64_t)ts.tv_nsec) / ns_per_second) return 0;
    *now = (uint64_t)ts.tv_sec * ns_per_second + (uint64_t)ts.tv_nsec;
    return 1;
}

static long elapsed(const struct cooldown_record *record, const char *boot_id, time_t now)
{
    if (!record->boot_id[0]) {
        if (now < 0 || (uint64_t)now < record->wall) return FAILOVER_COOLDOWN_LEGACY_FUTURE;
        uint64_t age = (uint64_t)now - record->wall;
        if (age < record->duration) return FAILOVER_COOLDOWN_BLOCKED;
        return age >= FAILOVER_MAX_COOLDOWN ? FAILOVER_MAX_COOLDOWN : (long)age;
    }

    uint64_t age;
    if (!*boot_id || !uptime_ns(&age)) return FAILOVER_COOLDOWN_BLOCKED;
    if (!strcmp(record->boot_id, boot_id)) {
        if (age < record->uptime_ns) return FAILOVER_COOLDOWN_BLOCKED;
        age -= record->uptime_ns;
    }
    /* Across boots, time since this boot is a lower bound on time since the attempt. */
    uint64_t seconds = age / ns_per_second;
    if (seconds < record->duration) return FAILOVER_COOLDOWN_BLOCKED;
    return seconds >= FAILOVER_MAX_COOLDOWN ? FAILOVER_COOLDOWN_EXPIRED : (long)seconds;
}

long failover_cooldown_age(const char *path, const char *boot_id, time_t now)
{
    struct cooldown_record record;
    int read = read_record(path, &record);
    if (read < 0) return FAILOVER_COOLDOWN_BLOCKED;
    return read ? elapsed(&record, boot_id, now) : FAILOVER_MAX_COOLDOWN;
}

static int open_parent(const char *path)
{
    char *parent = strdup(path);
    if (!parent) return -1;
    char *slash = strrchr(parent, '/');
    if (slash == parent) slash[1] = '\0';
    else if (slash) *slash = '\0';
    int dir = open(slash ? parent : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(parent);
    return dir;
}

int failover_cooldown_save(const char *path, const char *boot_id, time_t now, unsigned duration)
{
    uint64_t stamp;
    if (!*boot_id || duration > FAILOVER_MAX_COOLDOWN || !uptime_ns(&stamp)) return -1;
    int dir = open_parent(path);
    if (dir < 0) return -1;
    char *temp = NULL;
    int rc = -1;
    if (asprintf(&temp, "%s.XXXXXX", path) >= 0) {
        int fd = mkstemp(temp);
        if (fd >= 0) {
            uint64_t wall = now > 0 ? (uint64_t)now : 0;
            int written = dprintf(fd, "v2 %s %" PRIu64 " %u %" PRIu64 "\n", boot_id, wall, duration, stamp);
            int saved = written > 0 && !fsync(fd);
            int closed = close(fd);
            if (saved && !closed && !rename(temp, path)) rc = fsync(dir);
            else unlink(temp);
        }
        free(temp);
    }
    close(dir);
    return rc;
}

void failover_cooldown_maintain(const char *path, const char *boot_id, time_t now)
{
    struct cooldown_record record;
    if (read_record(path, &record) != 1) return;
    long age = elapsed(&record, boot_id, now);
    if (age == FAILOVER_COOLDOWN_LEGACY_FUTURE) {
        /* The old format cannot tell whether rollback occurred seconds after a switch. */
        failover_cooldown_save(path, boot_id, now, (unsigned)record.duration);
    } else if (age == FAILOVER_COOLDOWN_EXPIRED) {
        int dir = open_parent(path);
        if (dir >= 0) {
            if (!unlink(path)) fsync(dir);
            close(dir);
        }
    }
}
