#define _XOPEN_SOURCE 700
#include "login_files.h"
#include "utf8.h"
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { CREDENTIALS_LIMIT = 4096, LOGIN_TOKEN_LIMIT = 16384 };

struct file_location {
    int directory;
    char name[NAME_MAX + 1];
};

static int protected_directory(int fd, int final)
{
    struct stat directory;
    if (fstat(fd, &directory)) return 0;
    if (!S_ISDIR(directory.st_mode) || (directory.st_uid != 0 && directory.st_uid != geteuid()) ||
        ((directory.st_mode & (S_IWGRP | S_IWOTH)) && (final || !(directory.st_mode & S_ISVTX)))) {
        errno = EPERM;
        return 0;
    }
    return 1;
}

static int open_location(const char *path, struct file_location *location)
{
    if (!path || path[0] != '/' || strnlen(path, PATH_MAX) == PATH_MAX) {
        errno = EINVAL;
        return -1;
    }
    int directory = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) return -1;

    /* A root-owned sticky ancestor such as /tmp can contain a trusted private
     * directory. Every opened component must itself belong to root or us. */
    for (const char *part = path + 1; ; ) {
        const char *slash = strchr(part, '/');
        size_t length = slash ? (size_t)(slash - part) : strlen(part);
        if (!length || length > NAME_MAX || (length == 1 && part[0] == '.') ||
            (length == 2 && part[0] == '.' && part[1] == '.')) {
            errno = EINVAL;
            break;
        }
        if (!protected_directory(directory, !slash)) break;
        memcpy(location->name, part, length);
        location->name[length] = '\0';
        if (!slash) {
            location->directory = directory;
            return 0;
        }
        int child = openat(directory, location->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (child < 0) break;
        close(directory);
        directory = child;
        part = slash + 1;
    }
    int saved = errno;
    close(directory);
    errno = saved;
    return -1;
}

static int private_file(const struct stat *file)
{
    if (!S_ISREG(file->st_mode) || file->st_uid != geteuid() || file->st_nlink != 1 ||
        (file->st_mode & (S_IRWXG | S_IRWXO))) {
        errno = EPERM;
        return 0;
    }
    return 1;
}

/* Return 1 for an existing private file and 0 for a missing entry. */
static int inspect(const struct file_location *location, struct stat *file)
{
    if (fstatat(location->directory, location->name, file, AT_SYMLINK_NOFOLLOW))
        return errno == ENOENT ? 0 : -1;
    return private_file(file) ? 1 : -1;
}

static int same_file(const struct stat *first, const struct stat *second)
{
    return first->st_dev == second->st_dev && first->st_ino == second->st_ino;
}

static void clear_bytes(void *data, size_t length)
{
    volatile unsigned char *bytes = data;
    while (length--) *bytes++ = 0;
}

void login_credentials_clear(struct login_credentials *out)
{
    if (out) clear_bytes(out, sizeof(*out));
}

static int copy_field(json_object *object, const char *key, char *out, size_t size)
{
    json_object *value = NULL;
    if (!json_object_object_get_ex(object, key, &value) ||
        !json_object_is_type(value, json_type_string)) return 0;
    size_t length = json_object_get_string_len(value);
    const char *text = json_object_get_string(value);
    if (!length || length >= size || memchr(text, '\0', length)) return 0;
    memcpy(out, text, length + 1);
    return 1;
}

static int parse_credentials(const char *buffer, size_t length, struct login_credentials *out)
{
    json_tokener *parser = json_tokener_new();
    if (!parser) {
        errno = ENOMEM;
        return -1;
    }
    /* Validate the JSON syntax separately from non-ASCII content. Some json-c
     * releases reject raw multibyte characters with JSON_TOKENER_STRICT. */
    char syntax[CREDENTIALS_LIMIT + 1];
    int multibyte = 0;
    for (size_t i = 0; i < length; i++) {
        syntax[i] = buffer[i];
        if ((unsigned char)buffer[i] >= 128) {
            syntax[i] = 'x';
            multibyte = 1;
        }
    }
    syntax[length] = '\0';
    json_tokener_set_flags(parser, JSON_TOKENER_STRICT);
    json_object *object = json_tokener_parse_ex(parser, syntax, (int)length);
    size_t end = json_tokener_get_parse_end(parser);
    end += strspn(syntax + end, " \r\n\t");
    int valid = json_tokener_get_error(parser) == json_tokener_success && end == length;
    json_tokener_free(parser);
    clear_bytes(syntax, sizeof(syntax));
    if (valid && multibyte) {
        json_object_put(object);
        object = parse_utf8_json(buffer, length);
    }
    valid = valid && json_object_is_type(object, json_type_object) && json_object_object_length(object) == 2 &&
        copy_field(object, "username", out->username, sizeof(out->username)) &&
        copy_field(object, "password", out->password, sizeof(out->password));
    json_object_put(object);
    if (!valid) errno = EINVAL;
    return valid ? 0 : -1;
}

int login_credentials_read(const char *path, struct login_credentials *out)
{
    if (!out) {
        errno = EINVAL;
        return -1;
    }
    login_credentials_clear(out);
    struct file_location location;
    if (open_location(path, &location)) return -1;

    struct stat expected, actual;
    int fd = -1, result = -1;
    if (inspect(&location, &expected) != 1) goto done;
    fd = openat(location.directory, location.name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &actual) || !private_file(&actual) || !same_file(&expected, &actual)) goto done;

    char buffer[CREDENTIALS_LIMIT + 2] = {0};
    size_t length = 0;
    while (length < sizeof(buffer) - 1) {
        ssize_t count = read(fd, buffer + length, sizeof(buffer) - 1 - length);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) break;
        if (!count) {
            result = parse_credentials(buffer, length, out);
            break;
        }
        length += (size_t)count;
    }
    if (length > CREDENTIALS_LIMIT) errno = EFBIG;
    clear_bytes(buffer, sizeof(buffer));
done:
    {
        int saved = errno;
        if (fd >= 0) close(fd);
        close(location.directory);
        if (result) login_credentials_clear(out);
        errno = saved;
        return result;
    }
}

int login_files_distinct(const char *credentials, const char *token)
{
    if (!credentials || !token || !strcmp(credentials, token)) {
        errno = EINVAL;
        return -1;
    }
    struct file_location source, destination;
    if (open_location(credentials, &source)) return -1;
    struct stat login_file, token_file;
    int result = -1;
    if (inspect(&source, &login_file) == 1 && !open_location(token, &destination)) {
        int exists = inspect(&destination, &token_file);
        if (!exists || (exists == 1 && !same_file(&login_file, &token_file))) result = 0;
        if (exists == 1 && result) errno = EINVAL;
        int saved = errno;
        close(destination.directory);
        errno = saved;
    }
    int saved = errno;
    close(source.directory);
    errno = saved;
    return result;
}

static int write_all(int fd, const char *bytes, size_t length)
{
    while (length) {
        ssize_t count = write(fd, bytes, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            if (!count) errno = EIO;
            return -1;
        }
        bytes += count;
        length -= (size_t)count;
    }
    return 0;
}

static int open_temporary(const struct file_location *location, char *name, size_t size)
{
    for (unsigned attempt = 0; attempt < 16; attempt++) {
        snprintf(name, size, ".v2raya-token-%ld-%u", (long)getpid(), attempt);
        if (!strcmp(name, location->name)) continue;
        int fd = openat(location->directory, name,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0 || errno != EEXIST) return fd;
    }
    errno = EEXIST;
    return -1;
}

int login_token_replace(const char *path, const char *token)
{
    size_t length = token ? strnlen(token, LOGIN_TOKEN_LIMIT + 1) : 0;
    if (!length || length > LOGIN_TOKEN_LIMIT) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < length; i++)
        if ((unsigned char)token[i] < 33 || (unsigned char)token[i] >= 127) {
            errno = EINVAL;
            return -1;
        }

    struct file_location location;
    if (open_location(path, &location)) return -1;
    struct stat expected, actual;
    int old = inspect(&location, &expected);
    char name[64];
    int fd = old < 0 || fsync(location.directory) ? -1 : open_temporary(&location, name, sizeof(name));
    int result = -1;
    if (fd >= 0) {
        int written = !fchmod(fd, 0600) && !write_all(fd, token, length) &&
                      !write_all(fd, "\n", 1) && !fsync(fd);
        int saved = errno;
        int closed = close(fd);
        if (!written) errno = saved;
        int renamed = 0;
        if (written && !closed) {
            int current = inspect(&location, &actual);
            if (current >= 0 && (current != old || (old && !same_file(&expected, &actual))))
                errno = EBUSY;
            else if (current >= 0 && !renameat(location.directory, name, location.directory, location.name)) {
                renamed = 1;
                result = fsync(location.directory);
            }
        }
        saved = errno;
        if (!renamed) unlinkat(location.directory, name, 0);
        errno = saved;
    }
    int saved = errno;
    close(location.directory);
    errno = saved;
    return result;
}
