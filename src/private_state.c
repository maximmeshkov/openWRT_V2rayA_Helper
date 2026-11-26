#define _GNU_SOURCE
#include "private_state.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

enum state_entry { UNREAD, ABSENT, PRESENT };

struct private_state {
    int directory, lock;
    enum state_entry entry;
    struct stat identity;
    dev_t directory_device;
    ino_t directory_inode;
    struct private_state *next;
    char name[NAME_MAX + 1];
    char directory_path[];
};

static struct private_state *opened;

static int private_file(const struct stat *info)
{
    return S_ISREG(info->st_mode) && info->st_uid == geteuid() && info->st_nlink == 1 &&
           !(info->st_mode & (S_IRWXG | S_IRWXO));
}

static int private_directory(const struct stat *info)
{
    return S_ISDIR(info->st_mode) && info->st_uid == geteuid() &&
           !(info->st_mode & (S_IRWXG | S_IRWXO));
}

static int directory_current(const struct private_state *state)
{
    struct stat info;
    return !lstat(state->directory_path, &info) && private_directory(&info) &&
           info.st_dev == state->directory_device && info.st_ino == state->directory_inode;
}

static int same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static int open_lock(int directory, const char *name)
{
    char lock_name[NAME_MAX + 1];
    int length = snprintf(lock_name, sizeof(lock_name), "%s.lock", name);
    if (length < 0 || (size_t)length >= sizeof(lock_name)) return -1;
    int fd = openat(directory, lock_name, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    struct stat info;
    /* The process owns the lock. Forked probe workers do not retain it. */
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
    if (!fstat(fd, &info) && private_file(&info) && !fcntl(fd, F_SETLK, &lock)) return fd;
    close(fd);
    return -1;
}

static int same_name_or_lock(const char *a, const char *b)
{
    if (!strcmp(a, b)) return 1;
    size_t a_length = strlen(a), b_length = strlen(b);
    if (a_length > b_length) return a_length == b_length + 5 && !strncmp(a, b, b_length) &&
                                    !strcmp(a + b_length, ".lock");
    return b_length == a_length + 5 && !strncmp(a, b, a_length) && !strcmp(b + a_length, ".lock");
}

struct private_state *private_state_open(const char *path)
{
    if (!path || *path != '/') return NULL;
    const char *name = strrchr(path, '/');
    if (name == path || !name[1] || strlen(name + 1) > NAME_MAX ||
        !strcmp(name + 1, ".") || !strcmp(name + 1, "..")) return NULL;
    char parent[PATH_MAX];
    size_t length = (size_t)(name - path);
    while (length && path[length - 1] == '/') --length;
    if (!length || length >= sizeof(parent)) return NULL;
    memcpy(parent, path, length);
    parent[length] = '\0';
    int directory = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) return NULL;
    struct stat info;
    if (fstat(directory, &info) || !private_directory(&info)) {
        close(directory);
        return NULL;
    }
    /* POSIX locks on the same inode can be reacquired and released by the same process. */
    for (struct private_state *other = opened; other; other = other->next) {
        if (other->directory_device == info.st_dev && other->directory_inode == info.st_ino &&
            same_name_or_lock(name + 1, other->name)) {
            close(directory);
            return NULL;
        }
    }
    int lock = open_lock(directory, name + 1);
    struct private_state *state = lock >= 0 ? calloc(1, sizeof(*state) + length + 1) : NULL;
    if (!state) {
        if (lock >= 0) close(lock);
        close(directory);
        return NULL;
    }
    state->directory = directory;
    state->lock = lock;
    state->directory_device = info.st_dev;
    state->directory_inode = info.st_ino;
    strcpy(state->name, name + 1);
    memcpy(state->directory_path, parent, length + 1);
    state->next = opened;
    opened = state;
    return state;
}

static int name_matches(const struct private_state *state, const struct stat *identity)
{
    struct stat current;
    if (fstatat(state->directory, state->name, &current, AT_SYMLINK_NOFOLLOW))
        return !identity && errno == ENOENT;
    return identity && private_file(&current) && same_file(identity, &current);
}

static ssize_t read_retry(int fd, void *buffer, size_t length)
{
    ssize_t count;
    do count = read(fd, buffer, length); while (count < 0 && errno == EINTR);
    return count;
}

int private_state_read(struct private_state *state, void *buffer, size_t capacity, size_t *length)
{
    if (!state || !length || (!buffer && capacity)) return -1;
    *length = 0;
    state->entry = UNREAD;
    if (!directory_current(state)) return -1;
    int fd = openat(state->directory, state->name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        if (errno != ENOENT || !directory_current(state)) return -1;
        state->entry = ABSENT;
        return 0;
    }
    struct stat before;
    int valid = !fstat(fd, &before) && private_file(&before) && before.st_size >= 0 &&
                (uintmax_t)before.st_size <= capacity;
    size_t size = valid ? (size_t)before.st_size : 0;
    size_t offset = 0;
    while (offset < size) {
        ssize_t count = read_retry(fd, (unsigned char *)buffer + offset, size - offset);
        if (count <= 0) break;
        offset += (size_t)count;
    }
    unsigned char extra;
    valid = valid && offset == size && !read_retry(fd, &extra, 1) && name_matches(state, &before) &&
            directory_current(state);
    close(fd);
    if (!valid) return -1;
    state->entry = PRESENT;
    state->identity = before;
    *length = size;
    return 1;
}

static int open_temporary(const struct private_state *state, char name[64])
{
    for (unsigned suffix = 0; suffix < 16; ++suffix) {
        snprintf(name, 64, ".v2raya-state-%ld-%u", (long)getpid(), suffix);
        if (!strcmp(name, state->name)) continue;
        int fd = openat(state->directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0 || errno != EEXIST) return fd;
    }
    return -1;
}

static int write_record(int fd, const void *data, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(fd, (const unsigned char *)data + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        offset += (size_t)count;
    }
    return 1;
}

int private_state_write(struct private_state *state, const void *data, size_t length)
{
    if (!state || state->entry == UNREAD || (!data && length) || !directory_current(state)) return 0;
    char name[64];
    int fd = open_temporary(state, name);
    if (fd < 0) return 0;
    int dir = state->directory;
    int absent = state->entry == ABSENT;
    int renamed = 0;
    struct stat temporary;
    int written = !fchmod(fd, 0600) && write_record(fd, data, length) && !fstat(fd, &temporary);
    if (close(fd)) written = 0;
    /* Cooperative writers hold the same lock; refuse a changed directory entry. */
    if (written && name_matches(state, absent ? NULL : &state->identity) && directory_current(state)) {
        if (absent) {
            renamed = !syscall(SYS_renameat2, dir, name, dir, state->name, RENAME_NOREPLACE);
        } else {
            renamed = !renameat(dir, name, dir, state->name);
        }
    }
    struct stat current;
    int valid = renamed && !fstatat(dir, state->name, &current, AT_SYMLINK_NOFOLLOW) &&
                private_file(&current) && current.st_dev == temporary.st_dev && current.st_ino == temporary.st_ino &&
                directory_current(state);
    if (!renamed) unlinkat(dir, name, 0);
    if (valid) {
        state->entry = PRESENT;
        state->identity = current;
    } else if (renamed) {
        state->entry = UNREAD;
    }
    return valid;
}

void private_state_close(struct private_state *state)
{
    if (!state) return;
    struct private_state **entry = &opened;
    while (*entry != state) entry = &(*entry)->next;
    *entry = state->next;
    close(state->lock);
    close(state->directory);
    free(state);
}
