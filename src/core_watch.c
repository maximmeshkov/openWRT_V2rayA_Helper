#include "core_watch.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

struct process_info {
    pid_t parent;
    unsigned long long started;
    char name[16];
    char state;
};

struct listener_inodes {
    unsigned long long api, core, core_ipv6;
};

static int decimal(const char *text)
{
    return text && *text && strspn(text, "0123456789") == strlen(text);
}

static pid_t process_id(const char *name)
{
    if (!decimal(name) || strlen(name) > 10) return 0;
    unsigned long number = strtoul(name, NULL, 10);
    return number && number <= INT_MAX ? (pid_t)number : 0;
}

struct local_endpoint {
    int family, port;
    struct in_addr v4;
    struct in6_addr v6;
};

static struct local_endpoint management_endpoint(const char *api)
{
    static const char scheme[] = "http://";
    struct local_endpoint result = {0};
    if (!api || strncmp(api, scheme, sizeof(scheme) - 1)) return result;
    const char *host = api + sizeof(scheme) - 1;
    int ipv6 = *host == '[';
    if (ipv6) ++host;
    const char *end = strchr(host, ipv6 ? ']' : ':');
    char address[INET6_ADDRSTRLEN];
    if (!end || end == host || (size_t)(end - host) >= sizeof(address)) return result;
    memcpy(address, host, (size_t)(end - host));
    address[end - host] = '\0';
    if (ipv6 && *++end != ':') return result;
    const char *port = end + 1;
    if (!decimal(port) || strlen(port) > 5 || atoi(port) > 65535) return result;

    if (ipv6) {
        if (inet_pton(AF_INET6, address, &result.v6) != 1 || IN6_IS_ADDR_UNSPECIFIED(&result.v6) ||
            IN6_IS_ADDR_V4MAPPED(&result.v6) || IN6_IS_ADDR_MULTICAST(&result.v6) ||
            IN6_IS_ADDR_LINKLOCAL(&result.v6)) return result;
        result.family = AF_INET6;
    } else {
        if (inet_pton(AF_INET, address, &result.v4) != 1) return result;
        uint32_t ip = ntohl(result.v4.s_addr);
        if (!ip || ip == UINT32_MAX || IN_MULTICAST(ip)) return result;
        result.family = AF_INET;
    }
    result.port = atoi(port);
    return result;
}

int core_watch_local_api(const char *api)
{
    return management_endpoint(api).port != 0;
}

static const char *string_field(json_object *object, const char *key)
{
    json_object *value = NULL;
    if (!json_object_object_get_ex(object, key, &value) || !json_object_is_type(value, json_type_string))
        return NULL;
    return json_object_get_string(value);
}

static int configured_port(json_object *entry)
{
    json_object *value = json_object_object_get(entry, "port");
    if (!json_object_is_type(value, json_type_int)) return 0;
    int64_t port = json_object_get_int64(value);
    return port >= 1 && port <= 65535 ? (int)port : 0;
}

/* A negative result means a SOCKS ingress was present but could not be verified. */
static int socks_port(json_object *inbounds)
{
    int result = 0;
    const char *selected = NULL;
    for (size_t i = 0; i < json_object_array_length(inbounds); i++) {
        json_object *entry = json_object_array_get_idx(inbounds, i);
        const char *tag = string_field(entry, "tag");
        if (!tag || (strcmp(tag, "socks") && strcmp(tag, "socks_ipv4"))) continue;
        const char *protocol = string_field(entry, "protocol");
        const char *address = string_field(entry, "listen");
        int port = configured_port(entry);
        if (result || !protocol || strcmp(protocol, "socks") || !address ||
            (strcmp(address, "0.0.0.0") && strcmp(address, "127.0.0.1")) || !port) return -1;
        result = port;
        selected = tag;
    }
    if (!result) return 0;
    int companion = 0;
    for (size_t i = 0; i < json_object_array_length(inbounds); i++) {
        json_object *entry = json_object_array_get_idx(inbounds, i);
        const char *tag = string_field(entry, "tag");
        if ((tag && !strcmp(tag, selected)) || configured_port(entry) != result) continue;
        /* Without port sharing, v2rayA may add this IPv6-only mirror. */
        const char *protocol = string_field(entry, "protocol"), *address = string_field(entry, "listen");
        if (companion || strcmp(selected, "socks_ipv4") || !tag || strcmp(tag, "socks_ipv6") ||
            !protocol || strcmp(protocol, "socks") || !address || strcmp(address, "::1")) return -1;
        companion = 1;
    }
    return result;
}

static int api_listener_port(json_object *entry, const char *expected_listen)
{
    const char *protocol = string_field(entry, "protocol");
    const char *listen = string_field(entry, "listen");
    const char *address = string_field(json_object_object_get(entry, "settings"), "address");
    if (!protocol || strcmp(protocol, "dokodemo-door") || !listen || strcmp(listen, expected_listen) ||
        !address || strcmp(address, "127.0.0.1")) return 0;
    return configured_port(entry);
}

static int xray_api_port(json_object *config, json_object *inbounds)
{
    const char *api_tag = string_field(json_object_object_get(config, "api"), "tag");
    if (!api_tag || strcmp(api_tag, "api-out")) return 0;
    int port = 0, ipv6 = 0, split = 0;
    for (size_t i = 0; i < json_object_array_length(inbounds); i++) {
        json_object *entry = json_object_array_get_idx(inbounds, i);
        const char *tag = string_field(entry, "tag");
        if (!tag) continue;
        if (!strcmp(tag, "api-in") || !strcmp(tag, "api-in_ipv4")) {
            if (port) return 0;
            port = api_listener_port(entry, "127.0.0.1");
            if (!port) return 0;
            split = !strcmp(tag, "api-in_ipv4");
        } else if (!strcmp(tag, "api-in_ipv6")) {
            if (ipv6) return 0;
            ipv6 = api_listener_port(entry, "::1");
            if (!ipv6) return 0;
        }
    }
    if (!port || (ipv6 && (!split || ipv6 != port))) return 0;
    unsigned listeners = 0;
    for (size_t i = 0; i < json_object_array_length(inbounds); i++)
        if (configured_port(json_object_array_get_idx(inbounds, i)) == port) ++listeners;
    return listeners == (ipv6 ? 2u : 1u) ? port : 0;
}

static int watched_port(json_object *config, int *using_api)
{
    *using_api = 0;
    json_object *inbounds = json_object_object_get(config, "inbounds");
    if (!json_object_is_type(inbounds, json_type_array)) return 0;
    int port = socks_port(inbounds);
    if (port) return port;
    /* Stock v2rayA checks this built-in TCP listener when starting Xray. */
    port = xray_api_port(config, inbounds);
    *using_api = port != 0;
    return port;
}

static int read_proc(pid_t pid, const char *file, char *data, size_t capacity)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/%s", (long)pid, file);
    FILE *input = fopen(path, "re");
    if (!input) return errno == ENOENT || errno == ESRCH ? 0 : -1;
    size_t length = fread(data, 1, capacity - 1, input);
    int error = ferror(input), saved = errno;
    fclose(input);
    if (error) return saved == ENOENT || saved == ESRCH ? 0 : -1;
    if (length == capacity - 1) return -1;
    data[length] = '\0';
    return (int)length;
}

static int process_info(pid_t pid, struct process_info *info)
{
    char stat[1024];
    int result = read_proc(pid, "stat", stat, sizeof(stat));
    if (result <= 0) return result;
    char *first = strchr(stat, '('), *last = strrchr(stat, ')');
    if (!first || !last || last <= first || last[1] != ' ' ||
        (size_t)(last - first - 1) >= sizeof(info->name)) return -1;
    size_t length = (size_t)(last - first - 1);
    memcpy(info->name, first + 1, length);
    info->name[length] = '\0';
    char *save = NULL, *field = strtok_r(last + 2, " ", &save);
    if (!field || strlen(field) != 1) return -1;
    info->state = *field;
    for (int number = 4; number <= 22; number++) {
        field = strtok_r(NULL, " ", &save);
        if (!field) return -1;
        if (number == 4) {
            if (!decimal(field) || strlen(field) > 10) return -1;
            unsigned long parent = strtoul(field, NULL, 10);
            if (parent > INT_MAX) return -1;
            info->parent = (pid_t)parent;
        }
    }
    if (!decimal(field)) return -1;
    errno = 0;
    info->started = strtoull(field, NULL, 10);
    return errno ? -1 : 1;
}

enum address_scope { OTHER_ADDRESS, WILDCARD, LOOPBACK_V4, LOOPBACK_V6 };

static enum address_scope socket_scope(const char *address, int ipv6, int loopback_network)
{
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (!ipv6) {
        if (strlen(address) != 8 || sscanf(address, "%8x", &d) != 1) return OTHER_ADDRESS;
        if (!d) return WILDCARD;
        return (loopback_network ? (ntohl(d) >> 24) == 127 : d == htonl(INADDR_LOOPBACK)) ?
               LOOPBACK_V4 : OTHER_ADDRESS;
    }
    if (strlen(address) != 32 || sscanf(address, "%8x%8x%8x%8x", &a, &b, &c, &d) != 4 || a || b)
        return OTHER_ADDRESS;
    if (!c && !d) return WILDCARD;
    if (!c && d == htonl(1U)) return LOOPBACK_V6;
    int loopback = loopback_network ? (ntohl(d) >> 24) == 127 : d == htonl(INADDR_LOOPBACK);
    return c == htonl(0xffffU) && loopback ? LOOPBACK_V4 : OTHER_ADDRESS;
}

struct tcp_row {
    char local[33], remote[33];
    unsigned int port, peer_port, state, uid;
    unsigned long long inode;
};

static int tcp_row_parse(const char *line, struct tcp_row *row)
{
    return strchr(line, '\n') &&
           sscanf(line, " %*s %32[0-9A-Fa-f]:%4x %32[0-9A-Fa-f]:%4x %2x %*s %*s %*s %u %*s %llu",
                  row->local, &row->port, row->remote, &row->peer_port, &row->state,
                  &row->uid, &row->inode) == 7;
}

static int row_address_matches(const char *text, int ipv6, const struct local_endpoint *endpoint, int wildcard)
{
    uint32_t words[4];
    if (!ipv6) {
        return endpoint->family == AF_INET && strlen(text) == 8 && sscanf(text, "%8" SCNx32, words) == 1 &&
               (words[0] == endpoint->v4.s_addr || (wildcard && !words[0]));
    }

    if (strlen(text) != 32 || sscanf(text, "%8" SCNx32 "%8" SCNx32 "%8" SCNx32 "%8" SCNx32,
                                    words, words + 1, words + 2, words + 3) != 4) return 0;
    if (wildcard && !words[0] && !words[1] && !words[2] && !words[3]) return 1;
    if (endpoint->family == AF_INET)
        return !words[0] && !words[1] && words[2] == htonl(0xffffU) && words[3] == endpoint->v4.s_addr;
    return !memcmp(words, &endpoint->v6, sizeof(words));
}

static int socket_table(int ipv6, const struct local_endpoint *management, int inbound,
                        struct listener_inodes *inodes)
{
    FILE *table = fopen(ipv6 ? "/proc/net/tcp6" : "/proc/net/tcp", "re");
    if (!table) return ipv6 && errno == ENOENT;
    char line[512];
    int valid = fgets(line, sizeof(line), table) != NULL;
    while (valid && fgets(line, sizeof(line), table)) {
        struct tcp_row row;
        if (!tcp_row_parse(line, &row)) {
            valid = 0;
            break;
        }
        if (row.state != 0x0a) continue;
        enum address_scope scope = socket_scope(row.local, ipv6, 0);
        unsigned long long *result = NULL;
        if (row.port == (unsigned)management->port && row_address_matches(row.local, ipv6, management, 1))
            result = &inodes->api;
        if (scope != OTHER_ADDRESS && row.port == (unsigned)inbound)
            result = scope == LOOPBACK_V6 ? &inodes->core_ipv6 : &inodes->core;
        if (!result) continue;
        if (*result || !row.inode) {
            valid = 0;
            break;
        }
        *result = row.inode;
    }
    valid = valid && !ferror(table);
    fclose(table);
    return valid;
}

static int owns_socket(pid_t pid, unsigned long long inode)
{
    char path[80], target[64], link[64];
    snprintf(path, sizeof(path), "/proc/%ld/fd", (long)pid);
    snprintf(target, sizeof(target), "socket:[%llu]", inode);
    DIR *fds = opendir(path);
    if (!fds) return -1;
    int owned = 0;
    for (;;) {
        errno = 0;
        struct dirent *fd = readdir(fds);
        if (!fd) { if (errno) owned = -1; break; }
        if (!decimal(fd->d_name)) continue;
        ssize_t length = readlinkat(dirfd(fds), fd->d_name, link, sizeof(link) - 1);
        if (length < 0) {
            if (errno == ENOENT || errno == ESRCH) continue;
            owned = -1;
            break;
        }
        link[length] = '\0';
        if (!strcmp(link, target)) { owned = 1; break; }
    }
    closedir(fds);
    return owned;
}

static int matches_config(pid_t pid, const char *path, const char *config_path)
{
    if (!strcmp(path, config_path)) return 1;
    /* Resolve aliases as the candidate process sees them, including a relative
     * path from its own working directory and hard links to the generated file. */
    char process_path[PATH_MAX];
    const char *format = *path == '/' ? "/proc/%ld/root%s" : "/proc/%ld/cwd/%s";
    int length = snprintf(process_path, sizeof(process_path), format, (long)pid, path);
    if (length < 0 || (size_t)length >= sizeof(process_path)) return -1;
    struct stat expected, actual;
    if (stat(config_path, &expected) || stat(process_path, &actual)) return -1;
    return expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino;
}

static int is_core_run(pid_t pid, const char *config_path)
{
    char args[4096];
    int result = read_proc(pid, "cmdline", args, sizeof(args));
    if (result <= 0) return result;
    if (args[result - 1] != '\0') return -1;
    const char *end = args + result;
    const char *operation = args + strlen(args) + 1;
    if (operation == end || strcmp(operation, "run")) return 0;
    for (const char *arg = operation + sizeof("run"); arg < end && *arg; arg += strlen(arg) + 1) {
        if (!strcmp(arg, "-test") || !strcmp(arg, "--test") ||
            !strncmp(arg, "-test=", 6) || !strncmp(arg, "--test=", 7)) return 0;
    }
    for (const char *arg = operation + sizeof("run"); arg < end && *arg; arg += strlen(arg) + 1) {
        const char *path = NULL;
        if (!strncmp(arg, "--config=", 9)) path = arg + 9;
        else if (!strncmp(arg, "-config=", 8)) path = arg + 8;
        else if (!strcmp(arg, "--config") || !strcmp(arg, "-config")) path = arg + strlen(arg) + 1;
        if (!path || path == end || !*path) continue;
        int matches = matches_config(pid, path, config_path);
        if (matches) return matches;
    }
    return 0;
}

static int same_effective_user(pid_t pid);

static int find_management_owner(unsigned long long api_inode, struct core_watch_sample *sample)
{
    DIR *proc = opendir("/proc");
    if (!proc) return 0;
    int valid = 1;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(proc);
        if (!entry) { if (errno) valid = 0; break; }
        pid_t pid = process_id(entry->d_name);
        if (!pid) continue;
        struct process_info info;
        int inspected = process_info(pid, &info);
        if (inspected < 0) { valid = 0; break; }
        if (!inspected || info.state == 'Z' || info.state == 'X' || strcmp(info.name, "v2raya") ||
            !same_effective_user(pid)) continue;
        int owner = owns_socket(pid, api_inode);
        if (owner < 0 || (owner && sample->owner)) { valid = 0; break; }
        if (owner) {
            sample->owner = pid;
            sample->owner_started = info.started;
        }
    }
    closedir(proc);
    return valid && sample->owner;
}

static int find_managed_core(const char *config_path, struct core_watch_sample *sample)
{
    /* A previous Xray can still refer to the same path after v2rayA rewrites it.
     * Only a child of the current management owner can be its live core. */
    DIR *proc = opendir("/proc");
    if (!proc) return 0;
    int valid = 1;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(proc);
        if (!entry) { if (errno) valid = 0; break; }
        pid_t pid = process_id(entry->d_name);
        if (!pid) continue;
        struct process_info info;
        int inspected = process_info(pid, &info);
        if (inspected < 0) { valid = 0; break; }
        if (!inspected || info.parent != sample->owner || info.state == 'Z' || info.state == 'X' ||
            strcmp(info.name, "xray")) continue;
        int core = is_core_run(pid, config_path);
        if (core < 0 || (core && sample->core)) { valid = 0; break; }
        if (core) {
            sample->core = pid;
            sample->core_started = info.started;
        }
    }
    closedir(proc);
    return valid;
}

static int connect_endpoint(const struct local_endpoint *endpoint)
{
    int fd = socket(endpoint->family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_in v4 = {.sin_family = AF_INET, .sin_addr = endpoint->v4};
    struct sockaddr_in6 v6 = {.sin6_family = AF_INET6, .sin6_addr = endpoint->v6};
    int ipv6 = endpoint->family == AF_INET6;
    const struct sockaddr *address = ipv6 ? (const struct sockaddr *)&v6 : (const struct sockaddr *)&v4;
    socklen_t size = ipv6 ? sizeof(v6) : sizeof(v4);
    if (bind(fd, address, size) < 0) { close(fd); return -1; }
    v4.sin_port = v6.sin6_port = htons((uint16_t)endpoint->port);
    int error = 0;
    if (connect(fd, address, size) < 0) {
        error = errno;
        if (error == EINPROGRESS) {
            struct pollfd event = {.fd = fd, .events = POLLOUT};
            socklen_t length = sizeof(error);
            if (poll(&event, 1, 200) != 1 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) < 0)
                error = EIO;
        }
    }
    close(fd);
    return !error ? 1 : error == ECONNREFUSED ? 0 : -1;
}

static int connect_loopback(int port)
{
    const struct local_endpoint loopback = {.family = AF_INET, .port = port, .v4 = {htonl(INADDR_LOOPBACK)}};
    return connect_endpoint(&loopback);
}

static int same_owner_alive(const struct core_watch_sample *sample)
{
    struct process_info owner;
    return sample && sample->owner > 0 && process_info(sample->owner, &owner) == 1 &&
           owner.started == sample->owner_started && owner.state != 'Z' && owner.state != 'X' &&
           !strcmp(owner.name, "v2raya");
}

static int redirect_has_no_hooks(pid_t owner)
{
    static const char *const files[] = {"environ", "cmdline"};
    char data[16384];
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        int size = read_proc(owner, files[i], data, sizeof(data));
        if (size <= 0 || data[size - 1] != '\0') return 0;
        for (const char *item = data; item < data + size; item += strlen(item) + 1) {
            if (!i) {
                static const char transparent[] = "V2RAYA_TRANSPARENT_HOOK=", core[] = "V2RAYA_CORE_HOOK=";
                if ((!strncmp(item, transparent, sizeof(transparent) - 1) && item[sizeof(transparent) - 1]) ||
                    (!strncmp(item, core, sizeof(core) - 1) && item[sizeof(core) - 1])) return 0;
            } else if (*item == '-') {
                const char *arg = item + 1 + (item[1] == '-');
                size_t length = strcspn(arg, "=");
                if ((length == sizeof("transparent-hook") - 1 && !strncmp(arg, "transparent-hook", length)) ||
                    (length == sizeof("core-hook") - 1 && !strncmp(arg, "core-hook", length))) return 0;
            }
        }
    }
    return 1;
}

unsigned long long core_watch_redirect_listener(const struct core_watch_sample *sample)
{
    struct process_info core;
    if (!same_owner_alive(sample) || !sample->core_started || process_info(sample->core, &core) != 1 ||
        core.parent != sample->owner || core.started != sample->core_started ||
        core.state == 'Z' || core.state == 'X' || strcmp(core.name, "xray") ||
        !redirect_has_no_hooks(sample->owner)) return 0;
    unsigned long long inode = 0;
    for (int ipv6 = 0; ipv6 < 2; ++ipv6) {
        FILE *table = fopen(ipv6 ? "/proc/net/tcp6" : "/proc/net/tcp", "re");
        if (!table) {
            if (ipv6 && errno == ENOENT) continue;
            return 0;
        }
        char line[512];
        int valid = fgets(line, sizeof(line), table) != NULL;
        while (valid && fgets(line, sizeof(line), table)) {
            struct tcp_row row;
            if (!tcp_row_parse(line, &row)) { valid = 0; break; }
            if (row.port != 52345 || row.state != 0x0a) continue;
            if (inode || !row.inode || socket_scope(row.local, ipv6, 0) != WILDCARD ||
                owns_socket(sample->core, row.inode) != 1) { valid = 0; break; }
            inode = row.inode;
        }
        valid = valid && !ferror(table);
        fclose(table);
        if (!valid) return 0;
    }
    return inode;
}

static int service_owns_socket(pid_t owner, unsigned long long inode)
{
    int owned = owns_socket(owner, inode);
    if (owned) return owned;
    DIR *proc = opendir("/proc");
    if (!proc) return -1;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(proc);
        if (!entry) { if (errno) owned = -1; break; }
        pid_t pid = process_id(entry->d_name);
        if (!pid) continue;
        struct process_info info;
        int inspected = process_info(pid, &info);
        if (inspected < 0) { owned = -1; break; }
        if (inspected && info.parent == owner && info.state != 'Z' && info.state != 'X') {
            owned = owns_socket(pid, inode);
            if (owned) break;
        }
    }
    closedir(proc);
    return owned;
}

enum start_network {
    START_TCP = 1, START_UDP = 2, START_UDP6_LOOPBACK = 4,
    START_TCP_WILDCARD = 8, START_UDP_WILDCARD = 16
};

static unsigned inbound_network(json_object *entry, const char *protocol)
{
    if (!protocol) return 0;
    if (!strcasecmp(protocol, "http") || !strcasecmp(protocol, "vmess") ||
        !strcasecmp(protocol, "vless") || !strcasecmp(protocol, "trojan")) return START_TCP;
    if (strcasecmp(protocol, "dokodemo-door")) return START_TCP | START_UDP;

    const char *network = string_field(json_object_object_get(entry, "settings"), "network");
    if (!network || !*network) return START_TCP | START_UDP;
    unsigned mask = 0;
    for (const char *begin = network; ; ) {
        const char *end = strchr(begin, ',');
        size_t length = end ? (size_t)(end - begin) : strlen(begin);
        if (length == 3 && !strncasecmp(begin, "tcp", length)) mask |= START_TCP;
        if (length == 3 && !strncasecmp(begin, "udp", length)) mask |= START_UDP;
        if (!end) return mask;
        begin = end + 1;
    }
}

static unsigned required_binds(json_object *entry, const char *protocol, unsigned networks)
{
    if (!networks) return 0;
    const char *listen = string_field(entry, "listen");
    if (!listen) return 0;
    int wildcard = !strcmp(listen, "::") || !strcmp(listen, "0.0.0.0");
    if (!wildcard && strcmp(listen, "::1")) return 0;

    unsigned binds = 0;
    json_object *settings = json_object_object_get(entry, "settings");
    if (!strcasecmp(protocol, "socks")) {
        json_object *udp = json_object_object_get(settings, "udp");
        binds = START_TCP;
        if (json_object_is_type(udp, json_type_boolean) && json_object_get_boolean(udp)) binds |= START_UDP;
    } else if (!strcasecmp(protocol, "dokodemo-door")) {
        const char *configured = string_field(settings, "network");
        if (configured && *configured) binds = networks;
    } else if (!strcasecmp(protocol, "http")) {
        binds = START_TCP;
    }
    if (!wildcard) return (binds & START_UDP) ? START_UDP6_LOOPBACK : 0;
    /* Xray's generic Go listeners can bind both families for an IPv4 wildcard. */
    return ((binds & START_TCP) ? START_TCP_WILDCARD : 0) |
           ((binds & START_UDP) ? START_UDP_WILDCARD : 0);
}

static int start_socket_table(const char *path, int ipv6, enum start_network protocol,
                              const unsigned char *networks, unsigned api_port, pid_t owner)
{
    FILE *table = fopen(path, "re");
    if (!table) return ipv6 && errno == ENOENT ? 0 : -1;
    char line[512];
    int conflicts = 0, valid = fgets(line, sizeof(line), table) != NULL;
    while (valid && fgets(line, sizeof(line), table)) {
        struct tcp_row row;
        if (!tcp_row_parse(line, &row)) { valid = 0; break; }
        if (!row.inode || !networks[row.port] || (protocol == START_TCP && row.state == 0x07)) continue;
        unsigned expected = networks[row.port];
        enum address_scope scope = socket_scope(row.local, ipv6, 1);
        /* REDIRECT can bind a wildcard even when v2rayA has portSharing disabled. */
        int wildcard = expected & (protocol == START_TCP ? START_TCP_WILDCARD : START_UDP_WILDCARD);
        /* Stock port checking also skips unconnected UDP6. */
        int udp6_bind = ipv6 && protocol == START_UDP && (expected & START_UDP6_LOOPBACK) &&
                        (scope == LOOPBACK_V6 || scope == WILDCARD);
        int required_bind = wildcard || udp6_bind;
        if (!required_bind && (!(expected & protocol) || (ipv6 && row.state == 0x07))) continue;
        int owned = service_owns_socket(owner, row.inode);
        if (owned < 0) { valid = 0; break; }
        if (owned) continue;
        int local = required_bind || scope != OTHER_ADDRESS;
        if (row.port != api_port) {
            conflicts |= local ? CORE_PORT_FIXED_LOCAL : CORE_PORT_FIXED_OTHER;
            continue;
        }
        conflicts |= local ? CORE_PORT_API_LOCAL : CORE_PORT_API_OTHER;
        if (protocol == START_TCP && row.state == 0x0a) {
            enum address_scope exact = socket_scope(row.local, ipv6, 0);
            if (exact == LOOPBACK_V4 || (!ipv6 && exact == WILDCARD) ||
                (ipv6 && exact == WILDCARD && connect_loopback((int)api_port) == 1))
                conflicts |= CORE_PORT_API_TCP4;
        }
    }
    valid = valid && !ferror(table);
    fclose(table);
    return valid ? conflicts : -1;
}

int core_watch_start_conflicts(json_object *config, const struct core_watch_sample *sample)
{
    if (!same_owner_alive(sample)) return -1;
    json_object *inbounds = json_object_object_get(config, "inbounds");
    if (!json_object_is_type(inbounds, json_type_array)) return -1;
    unsigned api_port = (unsigned)xray_api_port(config, inbounds);
    unsigned char *networks = calloc(UINT16_MAX + 1U, sizeof(*networks));
    if (!networks) return -1;

    for (size_t i = 0; i < json_object_array_length(inbounds); ++i) {
        json_object *entry = json_object_array_get_idx(inbounds, i);
        const char *tag = string_field(entry, "tag");
        const char *protocol = string_field(entry, "protocol");
        int port = configured_port(entry);
        /* v2rayA's DNS entry is regenerated using a separate availability check. */
        if (tag && protocol && !strcasecmp(protocol, "dokodemo-door") && !strncmp(tag, "dns-in", 6)) continue;
        if (port) {
            unsigned mask = inbound_network(entry, protocol);
            unsigned binds = required_binds(entry, protocol, mask);
            networks[port] = (unsigned char)((networks[port] & ~(START_TCP | START_UDP)) | mask | binds);
        }
    }

    static const char *const tables[] = {"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"};
    int conflicts = 0;
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); ++i) {
        int result = start_socket_table(tables[i], i % 2, i < 2 ? START_TCP : START_UDP,
                                        networks, api_port, sample->owner);
        if (result < 0) { conflicts = -1; break; }
        conflicts |= result;
    }
    free(networks);
    return same_owner_alive(sample) ? conflicts : -1;
}

static int established_peer(int ipv6, const struct local_endpoint *endpoint, unsigned int client_port,
                            int *seen, unsigned long long *inode)
{
    FILE *table = fopen(ipv6 ? "/proc/net/tcp6" : "/proc/net/tcp", "re");
    if (!table) return ipv6 && errno == ENOENT;
    char line[512];
    int valid = fgets(line, sizeof(line), table) != NULL;
    while (valid && fgets(line, sizeof(line), table)) {
        struct tcp_row row;
        if (!tcp_row_parse(line, &row)) { valid = 0; break; }
        if (row.state != 1 || row.port != (unsigned)endpoint->port || row.peer_port != client_port ||
            !row_address_matches(row.local, ipv6, endpoint, 0) ||
            !row_address_matches(row.remote, ipv6, endpoint, 0)) continue;
        if (*seen || (row.inode && row.uid != geteuid())) { valid = 0; break; }
        *seen = 1;
        *inode = row.inode;
    }
    valid = valid && !ferror(table);
    fclose(table);
    return valid;
}

static int same_effective_user(pid_t pid)
{
    char path[64], line[128];
    snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);
    FILE *status = fopen(path, "re");
    if (!status) return 0;
    unsigned int uid;
    int same_user = 0;
    while (fgets(line, sizeof(line), status)) {
        if (!strncmp(line, "Uid:", 4)) {
            same_user = sscanf(line + 4, "%*u %u", &uid) == 1 && uid == geteuid();
            break;
        }
    }
    fclose(status);
    return same_user;
}

static int trusted_executable(pid_t pid)
{
    char link[64], name[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/%ld/exe", (long)pid);
    ssize_t length = readlink(link, name, sizeof(name) - 1);
    if (length <= 0 || (size_t)length == sizeof(name) - 1) return 0;
    name[length] = '\0';
    const char *base = strrchr(name, '/');
    if (!base || strcmp(base + 1, "v2raya")) return 0;

    int fd = open(link, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat info;
    unsigned char magic[4];
    int trusted = !fstat(fd, &info) && S_ISREG(info.st_mode) &&
                  (info.st_uid == 0 || info.st_uid == geteuid()) &&
                  !(info.st_mode & (S_IWGRP | S_IWOTH)) &&
                  read(fd, magic, sizeof(magic)) == sizeof(magic) && !memcmp(magic, "\x7f" "ELF", sizeof(magic));
    close(fd);
    return trusted;
}

static int local_ip_matches(const struct local_endpoint *endpoint, const char *address)
{
    if (!address) return 0;
    if (endpoint->family == AF_INET) {
        struct in_addr v4;
        return inet_pton(AF_INET, address, &v4) == 1 && v4.s_addr == endpoint->v4.s_addr;
    }
    struct in6_addr v6;
    return inet_pton(AF_INET6, address, &v6) == 1 && !memcmp(&v6, &endpoint->v6, sizeof(v6));
}

static int trusted_peer(const struct core_watch_peer *peer, const char *local_ip, unsigned local_port,
                        const char *remote_ip, unsigned remote_port)
{
    struct local_endpoint endpoint = management_endpoint(peer->api);
    if (!endpoint.port || remote_port != (unsigned)endpoint.port || !local_port || local_port > 65535 ||
        local_port == remote_port || !local_ip_matches(&endpoint, local_ip) ||
        !local_ip_matches(&endpoint, remote_ip)) return 0;

    /* The server-side inode can stay zero until v2rayA accepts the connection. */
    unsigned long long inode = 0;
    for (int attempt = 0; attempt < 10; ++attempt) {
        int seen = 0;
        if ((endpoint.family == AF_INET && !established_peer(0, &endpoint, local_port, &seen, &inode)) ||
            !established_peer(1, &endpoint, local_port, &seen, &inode)) return 0;
        if (inode) break;
        if (attempt == 9 || poll(NULL, 0, 20) < 0) return 0;
    }

    struct core_watch_sample sample = {0};
    /* The helper's effective UID and a system-owned executable are the trust boundary. */
    if (!find_management_owner(inode, &sample) || !same_effective_user(sample.owner) ||
        !trusted_executable(sample.owner) || !same_owner_alive(&sample) || owns_socket(sample.owner, inode) != 1)
        return 0;
    return !peer->expected || (sample.owner == peer->expected->owner &&
                               sample.owner_started == peer->expected->owner_started);
}

int core_watch_verify_peer(void *context, char *remote_ip, char *local_ip, int remote_port, int local_port)
{
    const struct core_watch_peer *peer = context;
    if (*peer->stopping || remote_port < 1 || local_port < 1) return 1;
    return !trusted_peer(peer, local_ip, (unsigned)local_port, remote_ip, (unsigned)remote_port) ||
           *peer->stopping;
}

int core_watch_still_absent(const struct core_watch_sample *sample)
{
    return sample && !sample->core && sample->port > 0 && sample->port <= 65535 &&
           same_owner_alive(sample) && connect_loopback(sample->port) == 0;
}

int core_watch_owner_childless(const struct core_watch_sample *sample)
{
    if (!same_owner_alive(sample) || !same_effective_user(sample->owner) ||
        !trusted_executable(sample->owner)) return 0;
    DIR *proc = opendir("/proc");
    if (!proc) return 0;
    int empty = 1;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(proc);
        if (!entry) { if (errno) empty = 0; break; }
        pid_t pid = process_id(entry->d_name);
        if (!pid) continue;
        struct process_info info;
        int inspected = process_info(pid, &info);
        if (inspected < 0 || (inspected && info.parent == sample->owner &&
                              info.state != 'Z' && info.state != 'X')) {
            empty = 0;
            break;
        }
    }
    closedir(proc);
    return empty && same_owner_alive(sample);
}

enum core_watch_state core_watch_sample(const char *api, const char *config_path,
                                        json_object *config, struct core_watch_sample *sample)
{
    if (!sample) return CORE_WATCH_UNKNOWN;
    *sample = (struct core_watch_sample){0};
    struct local_endpoint management = management_endpoint(api);
    int using_api;
    int port = watched_port(config, &using_api);
    if (!management.port || port <= 0 || management.port == port || !config_path || *config_path != '/')
        return CORE_WATCH_UNKNOWN;
    struct listener_inodes inodes = {0};
    if (!socket_table(0, &management, port, &inodes) || !socket_table(1, &management, port, &inodes) ||
        !inodes.api || !find_management_owner(inodes.api, sample) ||
        !find_managed_core(config_path, sample)) return CORE_WATCH_UNKNOWN;
    sample->port = port;
    if (!same_owner_alive(sample) || owns_socket(sample->owner, inodes.api) != 1 ||
        connect_endpoint(&management) != 1)
        return CORE_WATCH_UNKNOWN;
    if (sample->core && inodes.core && owns_socket(sample->core, inodes.core) == 1 &&
        (!inodes.core_ipv6 || owns_socket(sample->core, inodes.core_ipv6) == 1) &&
        connect_loopback(port) == 1)
        return CORE_WATCH_HEALTHY;
    if (!sample->core && !inodes.core && !inodes.core_ipv6 && connect_loopback(port) == 0)
        return CORE_WATCH_MISSING;
    if (!sample->core && (inodes.core || inodes.core_ipv6))
        return using_api ? CORE_WATCH_API_PORT_BUSY : CORE_WATCH_PORT_BUSY;
    return CORE_WATCH_UNKNOWN;
}
